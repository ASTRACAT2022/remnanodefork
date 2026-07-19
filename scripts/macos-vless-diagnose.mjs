#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { promises as dns } from 'node:dns';
import fs from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';

const DEFAULT_URLS = [
    'https://example.com/',
    'https://www.cloudflare.com/cdn-cgi/trace',
    'https://www.google.com/generate_204',
];

const DEFAULT_LOAD_URLS = [
    'https://speed.cloudflare.com/__down?bytes=50000000',
];

const CLOUDFLARE_LOAD_URL = 'https://speed.cloudflare.com/__down?bytes=';

const SUPPORTED_FINGERPRINTS = new Set([
    'chrome',
    'chrome_auto',
    'chrome_120',
    'chrome_124',
    'chrome_126',
    'chrome_128',
    'chrome_131',
    'chrome_133',
    'firefox',
    'firefox_auto',
    'firefox_120',
    'firefox_125',
    'safari',
    'safari_auto',
    'ios',
    'android',
    'edge',
    'yandex',
    'yandex_auto',
    'random',
    'randomized',
    'randomizednoalpn',
]);

function printHelp() {
    console.log(`Usage:
  node scripts/macos-vless-diagnose.mjs 'vless://...' [options]
  pbpaste | node scripts/macos-vless-diagnose.mjs - [options]

Options:
  --xray <path>      Xray binary path. Default: XRAY_BIN, xray from PATH, or common Homebrew paths
  --asset-dir <dir>  Xray asset dir. Sets XRAY_LOCATION_ASSET for Xray
  --url <url>        HTTPS URL to test through proxy. Can repeat
  --timeout <ms>     Timeout per check. Default: 8000
  --load-test        Download larger HTTPS objects through Xray to reproduce video-like drops
  --load-bytes <n>   Cloudflare load size. Supports plain bytes, 500m, 1g, 1gb, 1gib
  --load-url <url>   Load-test URL. Can repeat. Default: Cloudflare 50MB test object
  --load-first       Run sustained load before the smaller HTTPS URL checks
  --load-repeat <n>  Repeat each load-test URL. Default: 1
  --load-connect-timeout <sec>  TCP/TLS setup timeout for load curl. Default: 8
  --load-time <sec>  Max seconds per load-test URL. Default: 45
  --reality-handshake-max <n>        Max REALITY handshakes per window for patched Xray
  --reality-handshake-window-ms <ms> REALITY handshake limiter window for patched Xray
  --reality-handshake-min-ms <ms>    Min delay between REALITY handshakes for patched Xray
  --report-dir <dir> Directory for logs/report. Default: ~/Desktop/xray-vless-diagnostics-<time>
  --no-active        Do not start Xray, only parse/direct/test config
  --keep-running     Keep temporary Xray running after active checks
  --help             Show this help
`);
}

function parseArgs(argv) {
    const args = {
        active: true,
        assetDir: process.env.XRAY_LOCATION_ASSET || '',
        keepRunning: false,
        link: '',
        loadConnectTimeout: 8,
        loadFirst: false,
        loadRepeat: 1,
        loadTest: false,
        loadTime: 45,
        loadUrls: [],
        reportDir: '',
        realityHandshakeMax: 0,
        realityHandshakeMinMs: 0,
        realityHandshakeWindowMs: 0,
        timeout: 8000,
        urls: [],
        xray: process.env.XRAY_BIN || '',
    };

    for (let i = 0; i < argv.length; i += 1) {
        const arg = argv[i];
        if (arg === '--help' || arg === '-h') {
            args.help = true;
        } else if (arg === '--xray') {
            args.xray = argv[++i] || '';
        } else if (arg === '--asset-dir') {
            args.assetDir = argv[++i] || '';
        } else if (arg === '--url') {
            args.urls.push(argv[++i] || '');
        } else if (arg === '--timeout') {
            args.timeout = Number(argv[++i]);
        } else if (arg === '--load-test') {
            args.loadTest = true;
        } else if (arg === '--load-bytes') {
            args.loadTest = true;
            args.loadUrls.push(`${CLOUDFLARE_LOAD_URL}${parseByteSize(argv[++i] || '')}`);
        } else if (arg === '--load-url') {
            args.loadUrls.push(argv[++i] || '');
        } else if (arg === '--load-first') {
            args.loadFirst = true;
        } else if (arg === '--load-repeat') {
            args.loadRepeat = Number(argv[++i]);
        } else if (arg === '--load-connect-timeout') {
            args.loadConnectTimeout = Number(argv[++i]);
        } else if (arg === '--load-time') {
            args.loadTime = Number(argv[++i]);
        } else if (arg === '--reality-handshake-max') {
            args.realityHandshakeMax = Number(argv[++i]);
        } else if (arg === '--reality-handshake-window-ms') {
            args.realityHandshakeWindowMs = Number(argv[++i]);
        } else if (arg === '--reality-handshake-min-ms') {
            args.realityHandshakeMinMs = Number(argv[++i]);
        } else if (arg === '--report-dir') {
            args.reportDir = argv[++i] || '';
        } else if (arg === '--no-active') {
            args.active = false;
        } else if (arg === '--keep-running') {
            args.keepRunning = true;
        } else if (!args.link) {
            args.link = arg;
        } else {
            throw new Error(`Unknown argument: ${arg}`);
        }
    }

    if (!args.urls.length) args.urls = DEFAULT_URLS;
    if (!args.loadUrls.length) args.loadUrls = DEFAULT_LOAD_URLS;
    if (!Number.isFinite(args.timeout) || args.timeout < 1000) {
        throw new Error('--timeout must be a number >= 1000');
    }
    if (!Number.isFinite(args.loadTime) || args.loadTime < 5) {
        throw new Error('--load-time must be a number >= 5');
    }
    if (!Number.isFinite(args.loadConnectTimeout) || args.loadConnectTimeout < 1) {
        throw new Error('--load-connect-timeout must be a number >= 1');
    }
    if (!Number.isInteger(args.loadRepeat) || args.loadRepeat < 1) {
        throw new Error('--load-repeat must be an integer >= 1');
    }
    for (const [name, value] of [
        ['--reality-handshake-max', args.realityHandshakeMax],
        ['--reality-handshake-window-ms', args.realityHandshakeWindowMs],
        ['--reality-handshake-min-ms', args.realityHandshakeMinMs],
    ]) {
        if (!Number.isInteger(value) || value < 0) {
            throw new Error(`${name} must be an integer >= 0`);
        }
    }
    return args;
}

function parseByteSize(raw) {
    const value = String(raw).trim().toLowerCase();
    const match = value.match(/^(\d+(?:\.\d+)?)(b|k|kb|kib|m|mb|mib|g|gb|gib)?$/);
    if (!match) {
        throw new Error('--load-bytes must be bytes or a size like 500m, 1g, 1gb, 1gib');
    }

    const amount = Number(match[1]);
    const unit = match[2] || 'b';
    const multiplier = {
        b: 1,
        k: 1024,
        kb: 1000,
        kib: 1024,
        m: 1024 ** 2,
        mb: 1000 ** 2,
        mib: 1024 ** 2,
        g: 1024 ** 3,
        gb: 1000 ** 3,
        gib: 1024 ** 3,
    }[unit];
    const bytes = Math.floor(amount * multiplier);
    if (!Number.isSafeInteger(bytes) || bytes < 1) {
        throw new Error('--load-bytes must resolve to a positive safe byte count');
    }
    return bytes;
}

async function readLink(input) {
    if (input === '-') return (await readStdin()).trim();
    if (input) return input.trim();

    const paste = await runProcess('/usr/bin/pbpaste', [], 1500).catch(() => null);
    if (paste?.stdout?.trim().startsWith('vless://')) return paste.stdout.trim();
    throw new Error('No vless:// link found. Pass it as an argument, stdin, or copy it to clipboard.');
}

async function readStdin() {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    return Buffer.concat(chunks).toString('utf8');
}

function parseVlessLink(raw) {
    const url = new URL(raw);
    if (url.protocol !== 'vless:') throw new Error('Link must start with vless://');

    const q = url.searchParams;
    const network = q.get('type') || q.get('network') || 'tcp';
    const security = q.get('security') || 'none';
    const userId = safeDecode(url.username || '');
    const address = url.hostname;
    const port = Number(url.port || '443');

    if (!isUuid(userId)) throw new Error(`VLESS UUID shape is invalid: ${userId || 'missing'}`);
    if (!address) throw new Error('VLESS server address is missing');
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`VLESS port is invalid: ${url.port}`);

    return {
        address,
        encryption: q.get('encryption') || 'none',
        flow: q.get('flow') || '',
        fragment: safeDecode(url.hash.slice(1) || ''),
        headerType: q.get('headerType') || q.get('header') || '',
        host: q.get('host') || q.get('authority') || '',
        network,
        path: q.get('path') || '',
        port,
        publicKey: q.get('pbk') || q.get('publicKey') || '',
        raw,
        security,
        serviceName: q.get('serviceName') || '',
        shortId: q.get('sid') || q.get('shortId') || '',
        sni: q.get('sni') || q.get('serverName') || q.get('peer') || '',
        spiderX: q.get('spx') || '',
        userId,
        fingerprint: q.get('fp') || q.get('fingerprint') || '',
    };
}

function buildXrayConfig(link, httpPort, socksPort, reportDir) {
    const outbound = {
        protocol: 'vless',
        settings: {
            vnext: [
                {
                    address: link.address,
                    port: link.port,
                    users: [
                        {
                            encryption: link.encryption || 'none',
                            id: link.userId,
                        },
                    ],
                },
            ],
        },
        streamSettings: {
            network: link.network,
            security: link.security,
        },
        tag: 'proxy',
    };

    if (link.flow) outbound.settings.vnext[0].users[0].flow = link.flow;

    if (link.security === 'reality') {
        outbound.streamSettings.realitySettings = {
            fingerprint: link.fingerprint || 'chrome',
            publicKey: link.publicKey,
            serverName: link.sni || link.address,
            shortId: link.shortId,
            spiderX: link.spiderX || '/',
        };
    } else if (link.security === 'tls') {
        outbound.streamSettings.tlsSettings = {
            allowInsecure: false,
            serverName: link.sni || link.host || link.address,
        };
    }

    if (link.network === 'tcp') {
        outbound.streamSettings.tcpSettings = {};
        if (link.headerType) outbound.streamSettings.tcpSettings.header = { type: link.headerType };
    } else if (link.network === 'ws') {
        outbound.streamSettings.wsSettings = {
            headers: link.host ? { Host: link.host } : {},
            path: link.path || '/',
        };
    } else if (link.network === 'grpc') {
        outbound.streamSettings.grpcSettings = {
            serviceName: link.serviceName,
        };
    } else if (link.network === 'kcp') {
        outbound.streamSettings.kcpSettings = link.headerType
            ? { header: { type: link.headerType } }
            : {};
    }

    return {
        inbounds: [
            {
                listen: '127.0.0.1',
                port: httpPort,
                protocol: 'http',
                sniffing: {
                    destOverride: ['http', 'tls', 'quic'],
                    enabled: true,
                },
                tag: 'diagnostic-http',
            },
            {
                listen: '127.0.0.1',
                port: socksPort,
                protocol: 'socks',
                settings: { udp: true },
                sniffing: {
                    destOverride: ['http', 'tls', 'quic'],
                    enabled: true,
                },
                tag: 'diagnostic-socks',
            },
        ],
        log: {
            access: path.join(reportDir, 'xray-access.log'),
            dnsLog: true,
            error: path.join(reportDir, 'xray-error.log'),
            loglevel: 'debug',
        },
        outbounds: [
            outbound,
            {
                protocol: 'freedom',
                tag: 'direct',
            },
        ],
        routing: {
            domainStrategy: 'AsIs',
            rules: [],
        },
    };
}

class Reporter {
    constructor(reportDir) {
        this.reportDir = reportDir;
        this.logPath = path.join(reportDir, 'diagnostic.log');
        this.rows = [];
    }

    async init() {
        await fs.mkdir(this.reportDir, { recursive: true });
        await fs.writeFile(this.logPath, '');
    }

    async section(title) {
        await this.line(`\n== ${title} ==`);
    }

    async result(level, title, detail = '') {
        this.rows.push({ detail, level, title });
        const prefix = level === 'pass' ? '[PASS]' : level === 'warn' ? '[WARN]' : level === 'fail' ? '[FAIL]' : '[INFO]';
        await this.line(`${prefix} ${title}${detail ? `\n       ${detail}` : ''}`);
    }

    async line(text) {
        console.log(text);
        await fs.appendFile(this.logPath, `${text}\n`);
    }

    failCount() {
        return this.rows.filter((row) => row.level === 'fail').length;
    }
}

async function diagnoseLink(link, reporter) {
    await reporter.result('info', 'Parsed VLESS endpoint', `${link.address}:${link.port}`);
    await reporter.result('info', 'Transport', `${link.network} + ${link.security}`);
    await reporter.result('info', 'Name', link.fragment || 'not set');

    if (link.security === 'reality') {
        await reporter.result('info', 'REALITY SNI', link.sni || link.address);
        if (SUPPORTED_FINGERPRINTS.has(link.fingerprint || 'chrome')) {
            await reporter.result('pass', 'REALITY fingerprint is known', link.fingerprint || 'chrome');
        } else {
            await reporter.result('fail', 'REALITY fingerprint is unknown', link.fingerprint || 'missing');
        }
        await reporter.result(isRealityPublicKey(link.publicKey) ? 'pass' : 'fail', 'REALITY publicKey shape', mask(link.publicKey));
        await reporter.result(isRealityShortId(link.shortId) ? 'pass' : 'fail', 'REALITY shortId shape', link.shortId || 'empty');
        if (link.flow === 'xtls-rprx-vision') {
            await reporter.result('pass', 'VLESS Vision flow is set', link.flow);
        } else {
            await reporter.result('warn', 'VLESS Vision flow is not set', link.flow || 'missing');
        }
    }

    if (!['tcp', 'ws', 'grpc', 'kcp'].includes(link.network)) {
        await reporter.result('warn', 'Transport is not fully modeled by this tester', link.network);
    }
}

async function directNetworkChecks(link, timeout, reporter) {
    await tcpCheck(link.address, link.port, timeout, reporter, 'TCP to VLESS endpoint');

    const names = new Set([link.address, link.sni, link.host].filter(Boolean));
    for (const name of names) {
        if (net.isIP(name)) continue;
        await dnsCheck(name, reporter);
    }

    const tlsName = link.sni || link.host || link.address;
    if (tlsName && !net.isIP(tlsName)) {
        await tlsProbe(tlsName, 443, timeout, reporter);
    }
}

async function runXrayConfigTest(xray, configPath, timeout, xrayEnv, reporter) {
    const proc = await runProcess(xray, ['run', '-test', '-config', configPath], timeout, xrayEnv).catch((error) => ({
        code: -1,
        stderr: error.message,
        stdout: '',
    }));
    const output = summarizeOutput(proc.stdout, proc.stderr);
    if (proc.code === 0) {
        await reporter.result('pass', 'xray run -test passed', output);
    } else {
        await reporter.result('fail', `xray run -test failed with code ${proc.code}`, output);
    }
}

async function activeProxyChecks(xray, configPath, httpPort, urls, timeout, xrayEnv, keepRunning, loadOptions, reporter) {
    let proc;
    let stdout = '';
    let stderr = '';

    try {
        proc = spawn(xray, ['run', '-config', configPath], {
            env: xrayEnv,
            stdio: ['ignore', 'pipe', 'pipe'],
        });
        proc.stdout.on('data', (chunk) => {
            stdout += chunk.toString();
        });
        proc.stderr.on('data', (chunk) => {
            stderr += chunk.toString();
        });

        await waitForPort('127.0.0.1', httpPort, timeout);
        await reporter.result('pass', 'Temporary Xray started', `HTTP proxy: 127.0.0.1:${httpPort}`);

        const runLoadChecks = async () => {
            if (!loadOptions.enabled) return;
            await reporter.section('Sustained load');
            for (let repeat = 1; repeat <= loadOptions.repeat; repeat += 1) {
                if (loadOptions.repeat > 1) {
                    await reporter.result('info', 'Load iteration', `${repeat}/${loadOptions.repeat}`);
                }
                for (const url of loadOptions.urls) {
                    await curlLoadFetch(url, httpPort, loadOptions.seconds, loadOptions.connectTimeout, reporter);
                }
            }
        };

        if (loadOptions.first) {
            await runLoadChecks();
        }
        for (const url of urls) {
            await httpProxyFetch(url, httpPort, timeout, reporter);
        }
        for (const url of urls) {
            await curlProxyFetch(url, httpPort, timeout, reporter);
        }
        if (!loadOptions.first) {
            await runLoadChecks();
        }
    } catch (error) {
        await reporter.result('fail', 'Active Xray proxy check failed', error.message);
    } finally {
        if (stdout) await fs.writeFile(path.join(reporter.reportDir, 'xray-stdout.log'), stdout);
        if (stderr) await fs.writeFile(path.join(reporter.reportDir, 'xray-stderr.log'), stderr);

        if (proc && keepRunning) {
            await reporter.result('info', 'Temporary Xray kept running', `pid=${proc.pid}`);
        } else if (proc) {
            await stopProcess(proc);
        }
    }
}

async function tcpCheck(host, port, timeout, reporter, title) {
    const started = Date.now();
    try {
        const socket = await connectTcp(host, port, timeout);
        socket.destroy();
        await reporter.result('pass', title, `${host}:${port} in ${Date.now() - started}ms`);
    } catch (error) {
        await reporter.result('fail', title, `${host}:${port}: ${error.message}`);
    }
}

async function dnsCheck(host, reporter) {
    try {
        const records = await dns.lookup(host, { all: true });
        await reporter.result('pass', `DNS resolves ${host}`, records.map((record) => record.address).join(', '));
    } catch (error) {
        await reporter.result('fail', `DNS cannot resolve ${host}`, error.message);
    }
}

async function tlsProbe(host, port, timeout, reporter) {
    const started = Date.now();
    try {
        const socket = await new Promise((resolve, reject) => {
            const conn = tls.connect({ host, port, servername: host, timeout });
            conn.once('secureConnect', () => resolve(conn));
            conn.once('timeout', () => {
                conn.destroy();
                reject(new Error('timeout'));
            });
            conn.once('error', reject);
        });
        const cert = socket.getPeerCertificate();
        socket.destroy();
        await reporter.result('pass', 'Direct TLS to SNI works', `${host}:${port} in ${Date.now() - started}ms; CN=${cert.subject?.CN || 'n/a'}`);
    } catch (error) {
        await reporter.result('warn', 'Direct TLS to SNI failed', `${host}:${port}: ${error.message}`);
    }
}

async function httpProxyFetch(rawUrl, proxyPort, timeout, reporter) {
    const url = new URL(rawUrl);
    if (url.protocol !== 'https:') {
        await reporter.result('warn', 'Skipping non-HTTPS URL', rawUrl);
        return;
    }

    const started = Date.now();
    let socket;
    try {
        socket = await connectTcp('127.0.0.1', proxyPort, timeout);
        socket.write(`CONNECT ${url.hostname}:443 HTTP/1.1\r\nHost: ${url.hostname}:443\r\nProxy-Connection: keep-alive\r\n\r\n`);
        const head = await readUntil(socket, '\r\n\r\n', timeout);
        const firstLine = head.split('\r\n')[0] || head.trim();
        if (!/^HTTP\/1\.[01] 200\b/.test(head)) throw new Error(`CONNECT failed: ${firstLine}`);

        const secure = tls.connect({ servername: url.hostname, socket });
        await onceSecure(secure, timeout);
        secure.write(`GET ${url.pathname || '/'}${url.search} HTTP/1.1\r\nHost: ${url.hostname}\r\nConnection: close\r\n\r\n`);
        const response = await readUntilClose(secure, timeout);
        await reporter.result('pass', 'Node proxy HTTPS request succeeded', `${rawUrl} -> ${response.split('\r\n')[0] || 'no status'} in ${Date.now() - started}ms`);
    } catch (error) {
        if (socket) socket.destroy();
        await reporter.result('fail', 'Node proxy HTTPS request failed', `${rawUrl}: ${error.message}`);
    }
}

async function curlProxyFetch(rawUrl, proxyPort, timeout, reporter) {
    const started = Date.now();
    const timeoutSeconds = Math.max(1, Math.ceil(timeout / 1000));
    const proc = await runProcess(
        '/usr/bin/curl',
        [
            '-sS',
            '--http1.1',
            '--proxy',
            `http://127.0.0.1:${proxyPort}`,
            '--max-time',
            String(timeoutSeconds),
            '-o',
            '/dev/null',
            '-w',
            'http_code=%{http_code} remote_ip=%{remote_ip} time_total=%{time_total}',
            rawUrl,
        ],
        timeout + 1500,
    ).catch((error) => ({
        code: -1,
        stderr: error.message,
        stdout: '',
    }));

    const output = summarizeOutput(proc.stdout, proc.stderr);
    if (proc.code === 0 && /http_code=(2|3)\d\d/.test(proc.stdout)) {
        await reporter.result('pass', 'curl proxy HTTPS request succeeded', `${rawUrl} -> ${output} in ${Date.now() - started}ms`);
    } else {
        await reporter.result('fail', `curl proxy HTTPS request failed with code ${proc.code}`, `${rawUrl}: ${output}`);
    }
}

async function curlLoadFetch(rawUrl, proxyPort, seconds, connectTimeout, reporter) {
    const started = Date.now();
    const proc = await runProcess(
        '/usr/bin/curl',
        [
            '-L',
            '-sS',
            '--proxy',
            `http://127.0.0.1:${proxyPort}`,
            '--connect-timeout',
            String(connectTimeout),
            '--max-time',
            String(seconds),
            '-o',
            '/dev/null',
            '-w',
            'http_code=%{http_code} size_download=%{size_download} speed_download=%{speed_download} time_connect=%{time_connect} time_appconnect=%{time_appconnect} time_starttransfer=%{time_starttransfer} time_total=%{time_total} remote_ip=%{remote_ip}',
            rawUrl,
        ],
        seconds * 1000 + 2000,
    ).catch((error) => ({
        code: -1,
        stderr: error.message,
        stdout: '',
    }));

    const output = summarizeOutput(proc.stdout, proc.stderr);
    if (proc.code === 0 && /http_code=(2|3)\d\d/.test(proc.stdout)) {
        await reporter.result('pass', 'Sustained proxy download succeeded', `${rawUrl} -> ${output}; wall=${Date.now() - started}ms`);
    } else {
        await reporter.result('fail', `Sustained proxy download failed with code ${proc.code}`, `${rawUrl}: ${output}; wall=${Date.now() - started}ms`);
    }
}

function connectTcp(host, port, timeout) {
    return new Promise((resolve, reject) => {
        const socket = net.connect({ host, port });
        const timer = setTimeout(() => {
            socket.destroy();
            reject(new Error('timeout'));
        }, timeout);
        socket.once('connect', () => {
            clearTimeout(timer);
            resolve(socket);
        });
        socket.once('error', (error) => {
            clearTimeout(timer);
            reject(error);
        });
    });
}

function onceSecure(socket, timeout) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            socket.destroy();
            reject(new Error('TLS timeout'));
        }, timeout);
        socket.once('secureConnect', () => {
            clearTimeout(timer);
            resolve();
        });
        socket.once('error', (error) => {
            clearTimeout(timer);
            reject(error);
        });
    });
}

function readUntil(socket, marker, timeout) {
    return new Promise((resolve, reject) => {
        let buffer = '';
        const timer = setTimeout(() => {
            cleanup();
            reject(new Error('read timeout'));
        }, timeout);
        const onData = (chunk) => {
            buffer += chunk.toString('utf8');
            if (buffer.includes(marker)) {
                cleanup();
                resolve(buffer);
            }
        };
        const onError = (error) => {
            cleanup();
            reject(error);
        };
        function cleanup() {
            clearTimeout(timer);
            socket.off('data', onData);
            socket.off('error', onError);
        }
        socket.on('data', onData);
        socket.once('error', onError);
    });
}

function readUntilClose(socket, timeout) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        const timer = setTimeout(() => {
            cleanup();
            socket.destroy();
            reject(new Error('response timeout'));
        }, timeout);
        const onData = (chunk) => chunks.push(chunk);
        const onEnd = () => {
            cleanup();
            resolve(Buffer.concat(chunks).toString('utf8'));
        };
        const onError = (error) => {
            cleanup();
            reject(error);
        };
        function cleanup() {
            clearTimeout(timer);
            socket.off('data', onData);
            socket.off('end', onEnd);
            socket.off('error', onError);
        }
        socket.on('data', onData);
        socket.once('end', onEnd);
        socket.once('error', onError);
    });
}

async function waitForPort(host, port, timeout) {
    const deadline = Date.now() + timeout;
    let lastError;
    while (Date.now() < deadline) {
        try {
            const socket = await connectTcp(host, port, 500);
            socket.destroy();
            return;
        } catch (error) {
            lastError = error;
            await delay(150);
        }
    }
    throw new Error(`Timed out waiting for ${host}:${port}: ${lastError?.message || 'unknown'}`);
}

async function pickPort() {
    return new Promise((resolve, reject) => {
        const server = net.createServer();
        server.listen(0, '127.0.0.1', () => {
            const address = server.address();
            server.close(() => resolve(address.port));
        });
        server.once('error', reject);
    });
}

function randomLocalPort(except = 0) {
    let port = 20000 + Math.floor(Math.random() * 30000);
    if (port === except) port += 1;
    return port;
}

function runProcess(command, args, timeout, env = process.env) {
    return new Promise((resolve, reject) => {
        const proc = spawn(command, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
        let stdout = '';
        let stderr = '';
        const timer = setTimeout(() => {
            proc.kill('SIGKILL');
            reject(new Error(`${command} timed out after ${timeout}ms`));
        }, timeout);
        proc.stdout.on('data', (chunk) => {
            stdout += chunk.toString();
        });
        proc.stderr.on('data', (chunk) => {
            stderr += chunk.toString();
        });
        proc.once('error', (error) => {
            clearTimeout(timer);
            reject(error);
        });
        proc.once('close', (code) => {
            clearTimeout(timer);
            resolve({ code, stderr, stdout });
        });
    });
}

async function stopProcess(proc) {
    if (proc.exitCode !== null) return;
    proc.kill('SIGTERM');
    const done = new Promise((resolve) => proc.once('close', resolve));
    await Promise.race([
        done,
        delay(1000).then(() => {
            if (proc.exitCode === null) proc.kill('SIGKILL');
        }),
    ]);
}

async function findXray(preferred) {
    const candidates = [
        preferred,
        'xray',
        '/usr/local/bin/xray',
        '/opt/homebrew/bin/xray',
        '/tmp/xray-modern-utls',
    ].filter(Boolean);

    for (const candidate of candidates) {
        const result = await runProcess(candidate, ['version'], 2500).catch(() => null);
        if (result?.code === 0) return { path: candidate, version: summarizeOutput(result.stdout, result.stderr) };
    }
    throw new Error(`Xray binary not found. Use --xray /path/to/xray`);
}

function buildXrayEnv(args) {
    const env = { ...process.env };
    if (args.assetDir) env.XRAY_LOCATION_ASSET = path.resolve(args.assetDir);
    if (args.realityHandshakeMax > 0) env.XRAY_REALITY_HANDSHAKE_MAX_PER_WINDOW = String(args.realityHandshakeMax);
    if (args.realityHandshakeWindowMs > 0) env.XRAY_REALITY_HANDSHAKE_WINDOW_MS = String(args.realityHandshakeWindowMs);
    if (args.realityHandshakeMinMs > 0) env.XRAY_REALITY_HANDSHAKE_MIN_INTERVAL_MS = String(args.realityHandshakeMinMs);
    return env;
}

function summarizeOutput(stdout, stderr) {
    const lines = `${stdout || ''}${stderr ? `\n${stderr}` : ''}`
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean);
    return lines.slice(-12).join('\n       ');
}

function isUuid(value) {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(value || ''));
}

function isRealityPublicKey(value) {
    return /^[A-Za-z0-9_-]{43}$/.test(String(value || ''));
}

function isRealityShortId(value) {
    return /^[0-9a-fA-F]{0,16}$/.test(String(value || '')) && String(value || '').length % 2 === 0;
}

function mask(value) {
    const text = String(value || '');
    if (text.length <= 10) return text || 'missing';
    return `${text.slice(0, 5)}...${text.slice(-5)}`;
}

function safeDecode(value) {
    try {
        return decodeURIComponent(value);
    } catch {
        return String(value || '');
    }
}

function delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
    const args = parseArgs(process.argv.slice(2));
    if (args.help) {
        printHelp();
        return;
    }

    const link = parseVlessLink(await readLink(args.link));
    const reportDir =
        args.reportDir ||
        path.join(os.homedir(), 'Desktop', `xray-vless-diagnostics-${new Date().toISOString().replace(/[:.]/g, '-')}`);
    const reporter = new Reporter(reportDir);
    await reporter.init();

    await reporter.section('Environment');
    await reporter.result('info', 'Report directory', reportDir);
    await reporter.result('info', 'Node.js', process.version);
    await reporter.result('info', 'Platform', `${process.platform} ${process.arch}; ${os.release()}`);

    const xray = await findXray(args.xray);
    await reporter.result('info', 'Xray binary', xray.path);
    await reporter.result('info', 'Xray version', xray.version);

    const httpPort = args.active ? await pickPort() : randomLocalPort();
    const socksPort = args.active ? await pickPort() : randomLocalPort(httpPort);
    const config = buildXrayConfig(link, httpPort, socksPort, reportDir);
    const configPath = path.join(reportDir, 'generated-xray-config.json');
    const xrayEnv = buildXrayEnv(args);
    await fs.writeFile(configPath, `${JSON.stringify(config, null, 2)}\n`);
    await fs.writeFile(path.join(reportDir, 'parsed-vless.json'), `${JSON.stringify({ ...link, raw: '[redacted]' }, null, 2)}\n`);

    await reporter.section('VLESS link');
    await diagnoseLink(link, reporter);

    await reporter.section('Direct network');
    await directNetworkChecks(link, args.timeout, reporter);

    await reporter.section('Xray config validation');
    await runXrayConfigTest(xray.path, configPath, args.timeout, xrayEnv, reporter);

    if (args.active) {
        await reporter.section('Active proxy');
        await activeProxyChecks(
            xray.path,
            configPath,
            httpPort,
            args.urls,
            args.timeout,
            xrayEnv,
            args.keepRunning,
            {
                enabled: args.loadTest,
                connectTimeout: args.loadConnectTimeout,
                first: args.loadFirst,
                repeat: args.loadRepeat,
                seconds: args.loadTime,
                urls: args.loadUrls,
            },
            reporter,
        );
    }

    await reporter.section('Summary');
    await reporter.result(reporter.failCount() ? 'warn' : 'pass', 'Diagnostics complete', `Report saved to ${reportDir}`);
}

main().catch((error) => {
    console.error(`[FATAL] ${error.message}`);
    process.exit(1);
});
