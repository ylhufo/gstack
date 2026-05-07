/**
 * Local SOCKS5 bridge — accepts unauthenticated connections on 127.0.0.1:<ephemeral>
 * and relays them through an authenticated upstream SOCKS5 proxy.
 *
 * Why this exists: Chromium does not prompt for SOCKS5 auth at launch. To use
 * an auth-required upstream (residential SOCKS5 from a VPN provider, for
 * example), we run a no-auth listener locally that the browser talks to, and
 * the bridge handles the auth handshake with upstream.
 *
 * Architecture:
 *   Chromium  →  socks5://127.0.0.1:<ephemeral>  (this bridge, no auth)
 *                  └→ authenticated SOCKS5 to upstream  →  destination
 *
 * Ported from wintermute's scripts/socks-bridge.mjs with TS types, ephemeral
 * port (no hardcoded 1090), 127.0.0.1-only bind, and a stream-error policy
 * that closes the affected client connection without transport retries (a
 * SOCKS bridge is transport, not request-aware — retries can corrupt browser
 * traffic mid-stream).
 */

import * as net from 'net';
import { SocksClient, type SocksProxy } from 'socks';

export interface UpstreamConfig {
  host: string;
  port: number;
  userId?: string;
  password?: string;
}

export interface BridgeHandle {
  /** Local port the bridge is listening on (ephemeral). */
  port: number;
  /** Underlying server. Exposed for tests; production code uses close(). */
  server: net.Server;
  /** Close the listener and all in-flight client sockets. */
  close: () => Promise<void>;
}

const SOCKS5_VERSION = 0x05;
const NO_AUTH_METHOD = 0x00;
const CMD_CONNECT = 0x01;
const ATYP_IPV4 = 0x01;
const ATYP_DOMAINNAME = 0x03;
const ATYP_IPV6 = 0x04;
const REPLY_SUCCESS = 0x00;
const REPLY_GENERAL_FAILURE = 0x01;
const REPLY_HOST_UNREACHABLE = 0x04;
const UPSTREAM_CONNECT_TIMEOUT_MS = 15000;

function buildUpstream(upstream: UpstreamConfig): SocksProxy {
  return {
    host: upstream.host,
    port: upstream.port,
    type: 5,
    ...(upstream.userId ? { userId: upstream.userId } : {}),
    ...(upstream.password ? { password: upstream.password } : {}),
  };
}

function parseConnectRequest(reqData: Buffer): { host: string; port: number } | null {
  if (reqData.length < 7 || reqData[0] !== SOCKS5_VERSION || reqData[1] !== CMD_CONNECT) {
    return null;
  }
  const atyp = reqData[3];
  if (atyp === ATYP_IPV4) {
    if (reqData.length < 10) return null;
    const host = `${reqData[4]}.${reqData[5]}.${reqData[6]}.${reqData[7]}`;
    const port = reqData.readUInt16BE(8);
    return { host, port };
  }
  if (atyp === ATYP_DOMAINNAME) {
    const len = reqData[4];
    if (reqData.length < 5 + len + 2) return null;
    const host = reqData.subarray(5, 5 + len).toString('utf8');
    const port = reqData.readUInt16BE(5 + len);
    return { host, port };
  }
  if (atyp === ATYP_IPV6) {
    if (reqData.length < 22) return null;
    const parts: string[] = [];
    for (let i = 4; i < 20; i += 2) parts.push(reqData.readUInt16BE(i).toString(16));
    const host = parts.join(':');
    const port = reqData.readUInt16BE(20);
    return { host, port };
  }
  return null;
}

function writeReply(sock: net.Socket, code: number): void {
  // SOCKS5 reply: VER REP RSV ATYP BND.ADDR(0.0.0.0) BND.PORT(0)
  const reply = Buffer.from([SOCKS5_VERSION, code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]);
  try { sock.write(reply); } catch { /* peer already gone */ }
}

/**
 * Start a local SOCKS5 bridge that relays to an authenticated upstream.
 * Listens on 127.0.0.1 only (never 0.0.0.0). port: 0 picks an ephemeral port.
 *
 * Stream-error policy: on any error during a relayed connection, the affected
 * client socket and its upstream pair are destroyed. No transport retries.
 * Browser sees a proxy/connection error and surfaces it as such.
 */
export async function startSocksBridge(opts: {
  upstream: UpstreamConfig;
  port?: number;
}): Promise<BridgeHandle> {
  const upstreamProxy = buildUpstream(opts.upstream);
  const requestedPort = opts.port ?? 0;
  const inFlight = new Set<net.Socket>();

  const server = net.createServer((clientSocket) => {
    inFlight.add(clientSocket);
    clientSocket.once('close', () => inFlight.delete(clientSocket));

    // Handshake step 1: client greeting → respond no-auth.
    clientSocket.once('data', (greeting) => {
      if (greeting[0] !== SOCKS5_VERSION) {
        clientSocket.destroy();
        return;
      }
      try { clientSocket.write(Buffer.from([SOCKS5_VERSION, NO_AUTH_METHOD])); }
      catch { clientSocket.destroy(); return; }

      // Handshake step 2: client CONNECT request.
      clientSocket.once('data', async (reqData) => {
        const dest = parseConnectRequest(reqData);
        if (!dest) {
          writeReply(clientSocket, REPLY_GENERAL_FAILURE);
          clientSocket.destroy();
          return;
        }

        let upstreamSocket: net.Socket;
        try {
          const result = await SocksClient.createConnection({
            proxy: upstreamProxy,
            command: 'connect',
            destination: { host: dest.host, port: dest.port },
            timeout: UPSTREAM_CONNECT_TIMEOUT_MS,
          });
          upstreamSocket = result.socket;
        } catch {
          writeReply(clientSocket, REPLY_HOST_UNREACHABLE);
          clientSocket.destroy();
          return;
        }

        writeReply(clientSocket, REPLY_SUCCESS);

        // Pipe bidirectionally. On any error, kill BOTH sockets (no retries).
        const killBoth = () => {
          try { clientSocket.destroy(); } catch { /* already gone */ }
          try { upstreamSocket.destroy(); } catch { /* already gone */ }
        };
        clientSocket.on('error', killBoth);
        upstreamSocket.on('error', killBoth);
        clientSocket.on('close', () => { try { upstreamSocket.destroy(); } catch { /* already gone */ } });
        upstreamSocket.on('close', () => { try { clientSocket.destroy(); } catch { /* already gone */ } });

        clientSocket.pipe(upstreamSocket);
        upstreamSocket.pipe(clientSocket);
      });
    });

    clientSocket.on('error', () => clientSocket.destroy());
  });

  await new Promise<void>((resolve, reject) => {
    const onErr = (e: unknown) => { server.off('listening', onListen); reject(e); };
    const onListen = () => { server.off('error', onErr); resolve(); };
    server.once('error', onErr);
    server.once('listening', onListen);
    server.listen(requestedPort, '127.0.0.1');
  });

  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('socks-bridge: unexpected listener address');
  }

  return {
    port: address.port,
    server,
    close: async () => {
      for (const sock of inFlight) {
        try { sock.destroy(); } catch { /* already gone */ }
      }
      inFlight.clear();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

export interface UpstreamTestOpts {
  upstream: UpstreamConfig;
  /** Hostname to test connectivity to through the upstream. Default 1.1.1.1. */
  testHost?: string;
  /** Port. Default 443. */
  testPort?: number;
  /** Total time budget across all retries. Default 5000ms. */
  budgetMs?: number;
  /** Number of attempts. Default 3. */
  retries?: number;
  /** Backoff between attempts. Default 500ms. */
  backoffMs?: number;
}

/**
 * Pre-flight: verify the upstream proxy actually accepts our credentials and
 * can reach a known endpoint. Called before chromium.launch so failures
 * surface as a clear startup error instead of a confusing 'connection
 * refused' on first navigation.
 *
 * Retries a few times with backoff because residential VPNs can take a
 * second to fully establish on first connect.
 *
 * Throws on final failure. Caller is responsible for redacting any error
 * that may leak credentials.
 */
export async function testUpstream(opts: UpstreamTestOpts): Promise<{ ok: true; attempts: number; ms: number }> {
  const upstreamProxy = buildUpstream(opts.upstream);
  const testHost = opts.testHost ?? '1.1.1.1';
  const testPort = opts.testPort ?? 443;
  const budgetMs = opts.budgetMs ?? 5000;
  const retries = opts.retries ?? 3;
  const backoffMs = opts.backoffMs ?? 500;

  const start = Date.now();
  let lastErr: unknown;

  for (let attempt = 1; attempt <= retries; attempt++) {
    const elapsed = Date.now() - start;
    const remaining = budgetMs - elapsed;
    if (remaining <= 0) break;
    const perAttempt = Math.min(remaining, Math.max(500, Math.floor(budgetMs / retries)));

    try {
      const result = await SocksClient.createConnection({
        proxy: upstreamProxy,
        command: 'connect',
        destination: { host: testHost, port: testPort },
        timeout: perAttempt,
      });
      try { result.socket.destroy(); } catch { /* test connection done */ }
      return { ok: true, attempts: attempt, ms: Date.now() - start };
    } catch (err) {
      lastErr = err;
      if (attempt < retries) {
        const elapsedAfter = Date.now() - start;
        if (elapsedAfter + backoffMs >= budgetMs) break;
        await new Promise<void>((r) => setTimeout(r, backoffMs));
      }
    }
  }

  const reason = lastErr instanceof Error ? lastErr.message : String(lastErr);
  const err = new Error(`SOCKS5 upstream rejected or unreachable after ${retries} attempts (${Date.now() - start}ms): ${reason}`);
  (err as Error & { upstreamHost?: string; upstreamPort?: number }).upstreamHost = opts.upstream.host;
  (err as Error & { upstreamHost?: string; upstreamPort?: number }).upstreamPort = opts.upstream.port;
  throw err;
}
