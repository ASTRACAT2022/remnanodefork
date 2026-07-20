# AesingFlow: integration manual for proxy cores

There are two supported ways to use AesingFlow from a proxy core:

1. **SOCKS bridge** — use with unmodified Xray, sing-box, or any application
   supporting a SOCKS5 outbound.
2. **Native Go outbound** — use `proxy.Dialer` directly in a Go application or
   in a custom build of a proxy core. It avoids the local SOCKS hop and keeps
   one multiplexed AesingFlow QUIC connection.

The current integration carries **TCP CONNECT streams**. It is not a TUN/VPN
interface and does not turn UDP into TCP. An adapter must reject UDP explicitly
until AesingFlow datagram sessions are implemented end-to-end for that core.

## Select an approach

| Need | Recommended path |
| --- | --- |
| Official Xray or sing-box binary | SOCKS bridge |
| Own Go proxy/application | Native `proxy.Dialer` |
| Custom Xray/sing-box build | Native outbound adapter |
| UDP, QUIC, device VPN | Not supported by this TCP integration |

## TLS, certificates, and SNI

Certificate verification is always enabled. With a public certificate (for
example, Let's Encrypt), the operating-system trust store is enough. With a
private CA, load **only its public PEM certificate** into `tls.Config.RootCAs`.
Never put a server private key or a CA file into an `aesingflow://` link.

For a normal domain address, set `ServerName` to the same hostname:

```go
tlsConfig := &tls.Config{
	MinVersion: tls.VersionTLS13,
	ServerName: "de1.node.example", // certificate name and TLS SNI
}
```

SNI only needs an explicit override when the network address is an IP, CDN, or
different routing hostname but the certificate belongs to another hostname. Do
not set `InsecureSkipVerify`: AesingFlow rejects it.

## Immediate integration through SOCKS5

Run the client next to the core. It binds only to loopback by default:

```sh
go run ./cmd/aesingflow-proxy-client \
  -server de1.node.example:4433 \
  -token "$AESINGFLOW_TOKEN"
```

It exposes SOCKS5 at `127.0.0.1:8010`. Route the traffic that should use
AesingFlow to this outbound. Keep `socks5h` when testing so DNS is resolved at
the server exit:

```sh
curl --proxy socks5h://127.0.0.1:8010 https://ifconfig.me
```

### Xray fragment

Add a normal SOCKS outbound, then select its tag in the desired Xray routing
rules. This is an outbound fragment, not a complete configuration.

```json
{
  "outbounds": [
    {
      "tag": "aesingflow-socks",
      "protocol": "socks",
      "settings": {
        "servers": [{ "address": "127.0.0.1", "port": 8010 }]
      }
    }
  ]
}
```

### sing-box fragment

Add this object to `outbounds`, then route traffic to `aesingflow-socks` using
your usual sing-box rules:

```json
{
  "type": "socks",
  "tag": "aesingflow-socks",
  "server": "127.0.0.1",
  "server_port": 8010,
  "version": "5"
}
```

No source changes are needed in either project for this route. Do not publish
port 8010: this SOCKS listener intentionally has no separate SOCKS credentials
because it is protected by its loopback-only bind.

## Native integration in a Go core

`proxy.Dialer` is the stable integration boundary. It has the standard Go
method:

```go
DialContext(ctx context.Context, network, address string) (net.Conn, error)
```

Only `tcp`, `tcp4`, and `tcp6` are accepted, and `address` is `host:port`. A
hostname is sent to the server exit, where it is resolved. The returned
`net.Conn` supports read, write, and full deadlines.

### Minimal construction

```go
import (
	"crypto/tls"
	"net/http"

	"github.com/ASTRACAT2022/aesingflow/pkg/aesingflow"
	"github.com/ASTRACAT2022/aesingflow/proxy"
)

func newHTTPClient() (*http.Client, func() error, error) {
	flowClient, err := aesingflow.NewClient(aesingflow.ClientConfig{
		Address: "de1.node.example:4433",
		Token: "replace-with-secret-token",
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: "de1.node.example",
		},
		// Zero also selects this default rate.
		BrutalSendRate: aesingflow.DefaultBrutalSendRate,
		MaxStreams:     256,
	})
	if err != nil {
		return nil, nil, err
	}

	outbound, err := proxy.NewDialer(proxy.DialerConfig{Client: flowClient})
	if err != nil {
		return nil, nil, err
	}
	return &http.Client{
		Transport: &http.Transport{DialContext: outbound.DialContext},
	}, outbound.Close, nil
}
```

Create one client and one dialer per outbound profile, retain them for the
profile lifetime, and call `Dialer.Close()` on shutdown or replacement. Do not
make a new QUIC connection for every request.

### Adapter shape

Keep a core-specific adapter small. Its task is only destination/context
translation; TLS, token authentication, QUIC multiplexing, and Brutal settings
remain within AesingFlow.

```go
type aesingFlowOutbound struct { dialer *proxy.Dialer }

func (o *aesingFlowOutbound) DialTCP(ctx context.Context, host string, port uint16) (net.Conn, error) {
	address := net.JoinHostPort(host, strconv.Itoa(int(port)))
	return o.dialer.DialContext(ctx, "tcp", address)
}
```

Pass the core cancellation context straight through. Return errors as normal
outbound dial errors; do not create parallel retry loops in the adapter. If a
stream cannot open, the dialer drops its stale shared connection so a following
dial can reconnect.

## Building native Xray or sing-box adapters

Official Xray and sing-box binaries have fixed outbound type registries. A
native `aesingflow` JSON entry therefore needs an adapter compiled into a fork
or upstream build; it cannot be enabled only by pasting JSON into an official
release.

For either core, implement the following:

1. Define settings: `server`, `server_port`, `token`, optional
   `tls.server_name`, optional local CA path, `max_streams`, and optional
   `brutal_bps`.
2. Validate settings and build a verified `tls.Config`, then construct one
   `aesingflow.Client` and `proxy.Dialer` during outbound initialization.
3. Register outbound type `aesingflow` in that core's outbound factory.
4. Convert a TCP destination to `host:port` and call `Dialer.DialContext`.
5. Call `Dialer.Close()` from the core's stop/reload lifecycle hook.
6. Reject UDP clearly; never silently fall back or claim that it is tunneled.

Suggested schema for a future native adapter:

```json
{
  "type": "aesingflow",
  "tag": "de1",
  "server": "de1.node.example",
  "server_port": 4433,
  "token": "secret",
  "tls": { "server_name": "de1.node.example" },
  "brutal_bps": 250000000,
  "max_streams": 256
}
```

This is a proposed adapter schema, not a format accepted by present official
Xray or sing-box releases. Until a native adapter is compiled, use the SOCKS
bridge above.

## Brutal and throughput

Brutal defaults to **250000000 bit/s**. It is a sender-side ceiling: server
Brutal controls proxy downloads to a client; client Brutal controls uploads to
the server. It is not negotiated between peers.

Set it to a measured sustainable link speed, not NIC speed. Use
`DisableBrutal: true` to opt out to CUBIC. Avoid adding another unrelated
per-stream limiter in a core: it fights multiplexing and obscures throughput
diagnosis.

## Verification checklist

1. Verify the server UDP port and certificate chain for the configured name.
2. Confirm one TCP request reaches its destination through the outbound.
3. Test several parallel TCP requests; they should share one QUIC connection.
4. Confirm UDP is rejected or not routed to the TCP-only bridge.
5. Test cancellation and shutdown; a cancelled context stops a dial and
   `Dialer.Close()` releases the QUIC connection.
6. Measure download and upload independently before changing the Brutal rate.

For transport diagnostics, set `QLOGDIR` before starting a client or server;
the [SOCKS proxy guide](../proxy/README.md#to-diagnose-throughput) has an
example.
