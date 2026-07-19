#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { promises as dns } from 'node:dns';
import fs from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';

const SUPPORTED_FINGERPRINTS = new Map([
    ['chrome', 'chrome_133'],
    ['chrome_auto', 'chrome_133'],
    ['chrome_120', 'chrome_120'],
    ['chrome_124', 'chrome_120'],
    ['chrome_126', 'chrome_120'],
    ['chrome_128', 'chrome_131'],
    ['chrome_131', 'chrome_131'],
    ['chrome_133', 'chrome_133'],
    ['firefox', 'firefox_120'],
    ['firefox_auto', 'firefox_120'],
    ['firefox_120', 'firefox_120'],
    ['firefox_125', 'firefox_120'],
    ['safari', 'safari_16_0'],
    ['safari_auto', 'safari_16_0'],
    ['ios', 'ios_14'],
    ['android', 'android'],
    ['edge', 'edge_85'],
    ['yandex', 'chrome_133'],
    ['yandex_auto', 'chrome_133'],
    ['random', 'process-selected'],
    ['randomized', 'process-seeded'],
    ['randomizednoalpn', 'process-seeded'],
    ['helloyandex_auto', 'chrome_133'],
]);

const DEFAULT_URLS = ['https://example.com/', 'https://www.cloudflare.com/cdn-cgi/trace'];

function printHelp() {
    console.log(`Usage:
  node scripts/xray-config-tester.mjs <config.json> [options]
  node scripts/xray-config-tester.mjs - --xray /usr/local/bin/xray < config.json

Options:
  --xray <path>      Xray binary path. Default: XRAY_BIN or xray from PATH
  --asset-dir <dir>  Xray geo asset dir. Default: XRAY_LOCATION_ASSET or common paths
  --active           Start Xray on temporary local ports and test HTTP CONNECT
  --url <url>        URL to test through the local HTTP inbound. Can repeat
  --timeout <ms>     Network timeout. Default: 7000
  --no-run-test      Skip "xray run -test"
  --keep-temp        Keep temporary runtime config and logs
  --help             Show this help

The tester diagnoses:
  - static config traps that make "connection failed" misleading;
  - REALITY fingerprint/key/id shape;
  - direct TCP reachability to the VLESS server address;
  - Xray config validation;
  - optional active proxy requests through a temporary HTTP inbound.
`);
}

function parseArgs(argv) {
    const args = {
        active: false,
        assetDir: process.env.XRAY_LOCATION_ASSET || '',
        configPath: null,
        keepTemp: false,
        runTest: true,
        timeout: 7000,
        urls: [],
        xray: process.env.XRAY_BIN || 'xray',
    };

    for (let i = 0; i < argv.length; i += 1) {
        const arg = argv[i];
        if (arg === '--help' || arg === '-h') {
            args.help = true;
        } else if (arg === '--active') {
            args.active = true;
        } else if (arg === '--keep-temp') {
            args.keepTemp = true;
        } else if (arg === '--no-run-test') {
            args.runTest = false;
        } else if (arg === '--asset-dir') {
            args.assetDir = argv[++i];
        } else if (arg === '--xray') {
            args.xray = argv[++i];
        } else if (arg === '--url') {
            args.urls.push(argv[++i]);
        } else if (arg === '--timeout') {
            args.timeout = Number(argv[++i]);
        } else if (!args.configPath) {
            args.configPath = arg;
        } else {
            throw new Error(`Unknown argument: ${arg}`);
        }
    }

    if (!args.urls.length) args.urls = DEFAULT_URLS;
    if (!Number.isFinite(args.timeout) || args.timeout < 1000) {
        throw new Error('--timeout must be a number >= 1000');
    }
    return args;
}

async function readConfig(configPath) {
    const raw =
        configPath === '-'
            ? await readStdin()
            : await fs.readFile(configPath, 'utf8');
    try {
        return JSON.parse(raw);
    } catch (error) {
        throw new Error(`Config is not valid JSON: ${error.message}`);
    }
}

async function readStdin() {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    return Buffer.concat(chunks).toString('utf8');
}

function resultStore() {
    const rows = [];
    return {
        add(level, title, detail = '') {
            rows.push({ detail, level, title });
        },
        count(level) {
            return rows.filter((row) => row.level === level).length;
        },
        print() {
            for (const row of rows) {
                const prefix =
                    row.level === 'pass'
                        ? '[PASS]'
                        : row.level === 'warn'
                          ? '[WARN]'
                          : row.level === 'fail'
                            ? '[FAIL]'
                            : '[INFO]';
                console.log(`${prefix} ${row.title}${row.detail ? `\n       ${row.detail}` : ''}`);
            }
        },
    };
}

async function lintConfig(config, results, assetDir, xray) {
    const outbounds = Array.isArray(config.outbounds) ? config.outbounds : [];
    const realityOutbounds = outbounds.filter(
        (outbound) => outbound?.streamSettings?.security === 'reality',
    );

    if (!realityOutbounds.length) {
        results.add('fail', 'No REALITY outbound found', 'Expected streamSettings.security = "reality".');
    }

    for (const outbound of realityOutbounds) {
        lintRealityOutbound(outbound, results);
    }

    lintDns(config, results);
    lintRouting(config, results);
    lintInbounds(config, results);
    lintLogs(config, results);
    lintRemarks(config, results);
    await lintGeoAssets(config, results, assetDir, xray);
}

function lintRealityOutbound(outbound, results) {
    const reality = outbound.streamSettings?.realitySettings || {};
    const vnext = outbound.settings?.vnext?.[0];
    const user = vnext?.users?.[0];
    const fingerprint = reality.fingerprint || 'chrome';

    if (SUPPORTED_FINGERPRINTS.has(fingerprint)) {
        results.add(
            'pass',
            `REALITY fingerprint "${fingerprint}" is supported`,
            `Resolved profile: ${SUPPORTED_FINGERPRINTS.get(fingerprint)}.`,
        );
    } else {
        results.add(
            'fail',
            `Unsupported REALITY fingerprint "${fingerprint}"`,
            'The new core rejects unknown names during config validation.',
        );
    }

    if (vnext?.address && vnext?.port) {
        results.add('info', 'VLESS server endpoint', `${vnext.address}:${vnext.port}`);
    } else {
        results.add('fail', 'VLESS endpoint is incomplete', 'Missing settings.vnext[0].address or port.');
    }

    if (isUuid(user?.id)) {
        results.add('pass', 'VLESS user id has valid UUID shape');
    } else {
        results.add('fail', 'VLESS user id is not a valid UUID shape', String(user?.id || 'missing'));
    }

    if (user?.flow === 'xtls-rprx-vision') {
        results.add('pass', 'VLESS flow is xtls-rprx-vision');
    } else {
        results.add('warn', 'VLESS flow is not xtls-rprx-vision', String(user?.flow || 'missing'));
    }

    if (isRealityPublicKey(reality.publicKey)) {
        results.add('pass', 'REALITY publicKey shape looks valid');
    } else {
        results.add(
            'fail',
            'REALITY publicKey shape looks invalid',
            'Expected a 43-character base64url X25519 public key.',
        );
    }

    if (isRealityShortId(reality.shortId)) {
        results.add('pass', 'REALITY shortId shape looks valid');
    } else {
        results.add(
            'fail',
            'REALITY shortId shape looks invalid',
            'Expected even-length hex, up to 16 hex chars in common client configs.',
        );
    }

    if (reality.serverName) {
        results.add('info', 'REALITY SNI/serverName', reality.serverName);
    } else {
        results.add('fail', 'REALITY serverName is missing');
    }
}

function lintDns(config, results) {
    const hosts = config.dns?.hosts || {};
    const mappedToLoopback = Object.entries(hosts).filter(([, value]) => value === '127.0.0.1');
    for (const [domain] of mappedToLoopback) {
        results.add(
            'warn',
            `DNS host override sends ${domain} to 127.0.0.1`,
            'Any test to this domain will fail by design, not because REALITY is broken.',
        );
    }

    const servers = config.dns?.servers || [];
    if (servers.includes('fake')) {
        results.add('info', 'DNS uses fake server', 'Good to remember when debugging sniffed domains.');
    }
    if (servers.includes('8.8.8.8')) {
        results.add(
            'warn',
            'DNS fallback uses 8.8.8.8',
            'In filtered networks this resolver can be blocked or poisoned; compare with DoH/DoT if DNS symptoms appear.',
        );
    }
}

function lintRouting(config, results) {
    const blockedDomains = [];
    for (const rule of config.routing?.rules || []) {
        if (rule.outboundTag === 'block' && Array.isArray(rule.domain)) {
            blockedDomains.push(...rule.domain);
        }
    }

    const commonTestDomains = ['ifconfig.me', 'api.ipify.org', 'checkip.amazonaws.com'];
    const blockedTests = commonTestDomains.filter((domain) =>
        blockedDomains.some((rule) => rule.includes(domain)),
    );
    if (blockedTests.length) {
        results.add(
            'warn',
            'Common IP-check domains are routed to blackhole',
            `${blockedTests.join(', ')} will fail by config design.`,
        );
    }

    if (config.routing?.domainStrategy === 'IPIfNonMatch') {
        results.add(
            'info',
            'Routing domainStrategy is IPIfNonMatch',
            'Unmatched domains can trigger DNS resolution before routing.',
        );
    }
}

function lintInbounds(config, results) {
    for (const inbound of config.inbounds || []) {
        if (inbound.listen === '127.0.0.1') {
            results.add(
                'info',
                `Inbound "${inbound.tag || inbound.protocol}" listens on loopback`,
                'Only local applications on this host can use it.',
            );
        }
    }
}

function lintLogs(config, results) {
    const access = config.log?.access;
    if (!access) return;

    if (access.startsWith('/Users/') && process.platform !== 'darwin') {
        results.add(
            'fail',
            'log.access is a macOS path but this host is not macOS',
            access,
        );
        return;
    }

    results.add('info', 'Configured access log path', access);
}

function lintRemarks(config, results) {
    const remark = `${config.remarks || ''} ${config.meta?.serverDescription || ''}`;
    const realityNetwork = config.outbounds?.find(
        (outbound) => outbound?.streamSettings?.security === 'reality',
    )?.streamSettings?.network;
    if (/mkcp/i.test(remark) && realityNetwork !== 'kcp') {
        results.add(
            'warn',
            'Remark says mKCP but outbound network is not kcp',
            `Configured REALITY network: ${realityNetwork || 'missing'}.`,
        );
    }
}

async function lintGeoAssets(config, results, assetDir, xray) {
    const needed = findNeededGeoAssets(config);
    if (!needed.size) return;

    const candidates = uniquePaths([
        assetDir,
        process.env.XRAY_LOCATION_ASSET,
        xrayAssetCandidate(xray),
        '/usr/local/share/xray',
        path.resolve(process.cwd(), 'resources'),
        path.resolve(process.cwd(), 'Xray-core/resources'),
    ]);

    const checks = [];
    for (const dir of candidates) {
        checks.push({ dir, files: await existingGeoFiles(dir, needed) });
    }

    const complete = checks.find((check) => neededFilesPresent(check.files, needed));
    if (complete) {
        results.add(
            'pass',
            'Xray geo assets are available',
            `${complete.dir}: ${Array.from(complete.files).sort().join(', ')}`,
        );
        return;
    }

    const seen = checks
        .filter((check) => check.files.size)
        .map((check) => `${check.dir}: ${Array.from(check.files).sort().join(', ')}`);
    results.add(
        'fail',
        'Xray geo assets are missing',
        `Config uses ${Array.from(needed).sort().join(', ')} rules, so xray needs ${Array.from(needed)
            .sort()
            .join(' and ')}.dat. Checked: ${candidates.join(', ')}.${seen.length ? ` Found partial: ${seen.join('; ')}` : ''}`,
    );
}

function findNeededGeoAssets(config) {
    const needed = new Set();
    for (const rule of config.routing?.rules || []) {
        for (const value of rule.ip || []) {
            if (String(value).startsWith('geoip:')) needed.add('geoip');
        }
        for (const value of rule.domain || []) {
            if (String(value).startsWith('geosite:')) needed.add('geosite');
        }
    }
    return needed;
}

function uniquePaths(paths) {
    return [...new Set(paths.filter(Boolean).map((item) => path.resolve(String(item))))];
}

function xrayAssetCandidate(xray) {
    const value = String(xray || '');
    if (!value.includes('/') && !value.includes(path.sep)) return '';
    return path.dirname(path.resolve(value));
}

async function existingGeoFiles(dir, needed) {
    const files = new Set();
    for (const name of needed) {
        const file = `${name}.dat`;
        try {
            const stat = await fs.stat(path.join(dir, file));
            if (stat.isFile()) files.add(file);
        } catch {
            // Missing assets are reported after checking every candidate path.
        }
    }
    return files;
}

function neededFilesPresent(files, needed) {
    for (const name of needed) {
        if (!files.has(`${name}.dat`)) return false;
    }
    return true;
}

function isUuid(value) {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
        String(value || ''),
    );
}

function isRealityPublicKey(value) {
    return /^[A-Za-z0-9_-]{43}$/.test(String(value || ''));
}

function isRealityShortId(value) {
    return /^[0-9a-fA-F]{0,16}$/.test(String(value || '')) && String(value || '').length % 2 === 0;
}

async function runXrayTest(xray, config, configPath, timeout, assetDir, results) {
    const temp = await makeTempRuntimeConfig(config, { keepInbounds: true });
    const testConfigPath = configPath === '-' ? temp.configPath : configPath;
    const cleanup = configPath === '-' ? temp.cleanup : async () => {};
    try {
        const proc = await runProcess(xray, ['run', '-test', '-config', testConfigPath], timeout, assetEnv(assetDir));
        if (proc.code === 0) {
            results.add('pass', 'xray run -test passed', summarizeOutput(proc.stdout, proc.stderr));
        } else {
            results.add(
                'fail',
                `xray run -test failed with code ${proc.code}`,
                summarizeOutput(proc.stdout, proc.stderr),
            );
        }
    } catch (error) {
        results.add('fail', 'xray run -test failed to execute', error.message);
    } finally {
        await cleanup();
    }
}

async function runDirectNetworkChecks(config, timeout, results) {
    const outbound = config.outbounds?.find((item) => item?.streamSettings?.security === 'reality');
    const vnext = outbound?.settings?.vnext?.[0];
    const reality = outbound?.streamSettings?.realitySettings;
    if (!vnext?.address || !vnext?.port) return;

    await tcpCheck(vnext.address, Number(vnext.port), timeout, results);
    if (reality?.serverName) {
        await dnsCheck(reality.serverName, results);
        await tlsProbe(reality.serverName, 443, timeout, results);
    }
}

async function tcpCheck(host, port, timeout, results) {
    const started = Date.now();
    try {
        const socket = await connectTcp(host, port, timeout);
        socket.destroy();
        results.add('pass', `TCP connect to VLESS server works`, `${host}:${port} in ${Date.now() - started}ms`);
    } catch (error) {
        results.add('fail', `TCP connect to VLESS server failed`, `${host}:${port}: ${error.message}`);
    }
}

async function dnsCheck(host, results) {
    try {
        const records = await dns.lookup(host, { all: true });
        results.add(
            'pass',
            `System DNS resolves REALITY serverName`,
            `${host} -> ${records.map((record) => record.address).join(', ')}`,
        );
    } catch (error) {
        results.add('warn', `System DNS cannot resolve REALITY serverName`, `${host}: ${error.message}`);
    }
}

async function tlsProbe(host, port, timeout, results) {
    const started = Date.now();
    try {
        const socket = await new Promise((resolve, reject) => {
            const conn = tls.connect({
                host,
                port,
                servername: host,
                timeout,
            });
            conn.once('secureConnect', () => resolve(conn));
            conn.once('timeout', () => {
                conn.destroy();
                reject(new Error('timeout'));
            });
            conn.once('error', reject);
        });
        const cert = socket.getPeerCertificate();
        socket.destroy();
        results.add(
            'pass',
            `Direct TLS probe to REALITY serverName works`,
            `${host}:${port} in ${Date.now() - started}ms; cert CN=${cert.subject?.CN || 'n/a'}`,
        );
    } catch (error) {
        results.add('warn', `Direct TLS probe to REALITY serverName failed`, `${host}:${port}: ${error.message}`);
    }
}

async function runActiveProxyChecks(xray, config, urls, timeout, keepTemp, assetDir, results) {
    const httpPort = await pickPort();
    const socksPort = await pickPort();
    const temp = await makeTempRuntimeConfig(config, {
        httpPort,
        keepInbounds: false,
        socksPort,
    });

    let proc;
    try {
        proc = spawn(xray, ['run', '-config', temp.configPath], {
            env: assetEnv(assetDir),
            stdio: ['ignore', 'pipe', 'pipe'],
        });
        let stdout = '';
        let stderr = '';
        proc.stdout.on('data', (chunk) => {
            stdout += chunk.toString();
        });
        proc.stderr.on('data', (chunk) => {
            stderr += chunk.toString();
        });

        await waitForPort('127.0.0.1', httpPort, timeout);
        results.add('pass', 'Temporary Xray started', `HTTP inbound: 127.0.0.1:${httpPort}`);

        for (const url of urls) {
            await httpProxyFetch(url, httpPort, timeout, results);
        }

        proc.kill('SIGTERM');
        await delay(500);
        if (stdout || stderr) {
            results.add('info', 'Xray runtime output tail', summarizeOutput(stdout, stderr));
        }
    } catch (error) {
        results.add('fail', 'Active proxy check failed', error.message);
        if (proc) proc.kill('SIGTERM');
    } finally {
        if (keepTemp) {
            results.add('info', 'Temporary files kept', temp.dir);
        } else {
            await temp.cleanup();
        }
    }
}

async function httpProxyFetch(rawUrl, proxyPort, timeout, results) {
    const url = new URL(rawUrl);
    if (url.protocol !== 'https:') {
        results.add('warn', `Skipping non-HTTPS URL`, rawUrl);
        return;
    }

    const started = Date.now();
    let socket;
    try {
        socket = await connectTcp('127.0.0.1', proxyPort, timeout);
        socket.write(
            `CONNECT ${url.hostname}:443 HTTP/1.1\r\nHost: ${url.hostname}:443\r\nProxy-Connection: keep-alive\r\n\r\n`,
        );
        const head = await readUntil(socket, '\r\n\r\n', timeout);
        if (!/^HTTP\/1\.[01] 200\b/.test(head)) {
            throw new Error(`CONNECT failed: ${head.split('\r\n')[0] || head}`);
        }

        const secure = tls.connect({
            servername: url.hostname,
            socket,
        });
        await onceSecure(secure, timeout);
        secure.write(`GET ${url.pathname || '/'}${url.search} HTTP/1.1\r\nHost: ${url.hostname}\r\nConnection: close\r\n\r\n`);
        const response = await readUntilClose(secure, timeout);
        const status = response.split('\r\n')[0] || 'no HTTP status';
        results.add('pass', `Proxy HTTPS request succeeded`, `${rawUrl} -> ${status} in ${Date.now() - started}ms`);
    } catch (error) {
        if (socket) socket.destroy();
        results.add('fail', `Proxy HTTPS request failed`, `${rawUrl}: ${error.message}`);
    }
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

async function makeTempRuntimeConfig(config, options) {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'xray-config-test-'));
    const runtimeConfig = structuredClone(config);
    runtimeConfig.log = {
        ...(runtimeConfig.log || {}),
        access: path.join(dir, 'access.log'),
        dnsLog: true,
        error: path.join(dir, 'error.log'),
        loglevel: 'debug',
    };

    if (!options.keepInbounds) {
        runtimeConfig.inbounds = [
            {
                listen: '127.0.0.1',
                port: options.httpPort,
                protocol: 'http',
                sniffing: {
                    destOverride: ['http', 'tls'],
                    enabled: true,
                },
                tag: 'diagnostic-http',
            },
            {
                listen: '127.0.0.1',
                port: options.socksPort,
                protocol: 'socks',
                settings: { udp: true },
                sniffing: {
                    destOverride: ['http', 'tls', 'quic'],
                    enabled: true,
                },
                tag: 'diagnostic-socks',
            },
        ];
    }

    delete runtimeConfig.meta;
    delete runtimeConfig.remarks;

    const configPath = path.join(dir, 'config.json');
    await fs.writeFile(configPath, `${JSON.stringify(runtimeConfig, null, 2)}\n`);
    return {
        configPath,
        dir,
        async cleanup() {
            await fs.rm(dir, { force: true, recursive: true });
        },
    };
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

function assetEnv(assetDir) {
    return assetDir
        ? {
              ...process.env,
              XRAY_LOCATION_ASSET: path.resolve(assetDir),
          }
        : process.env;
}

function summarizeOutput(stdout, stderr) {
    const lines = `${stdout || ''}${stderr ? `\n${stderr}` : ''}`
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean);
    return lines.slice(-8).join('\n       ');
}

function delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
    const args = parseArgs(process.argv.slice(2));
    if (args.help || !args.configPath) {
        printHelp();
        process.exit(args.help ? 0 : 1);
    }

    const config = await readConfig(args.configPath);
    const results = resultStore();

    console.log('== Static config diagnostics ==');
    await lintConfig(config, results, args.assetDir, args.xray);
    results.print();

    console.log('\n== Direct network diagnostics ==');
    const directResults = resultStore();
    await runDirectNetworkChecks(config, args.timeout, directResults);
    directResults.print();

    if (args.runTest) {
        console.log('\n== Xray config validation ==');
        const xrayResults = resultStore();
        await runXrayTest(args.xray, config, args.configPath, args.timeout, args.assetDir, xrayResults);
        xrayResults.print();
    }

    if (args.active) {
        console.log('\n== Active proxy diagnostics ==');
        const activeResults = resultStore();
        await runActiveProxyChecks(args.xray, config, args.urls, args.timeout, args.keepTemp, args.assetDir, activeResults);
        activeResults.print();
    }
}

main().catch((error) => {
    console.error(`[FATAL] ${error.message}`);
    process.exit(1);
});
