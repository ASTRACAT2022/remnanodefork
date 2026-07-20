# Core integrations

For the full step-by-step guide, including Xray and sing-box SOCKS fragments
and the lifecycle of a native Go adapter, see the
[core integration manual](core-integration-manual.md).

AesingFlow separates its QUIC transport from the local SOCKS5 command. The
`proxy.Dialer` package is the stable outbound integration API: it implements
`DialContext(context.Context, network, address) (net.Conn, error)` and keeps one
multiplexed AesingFlow connection for the host core.

It supports TCP (`tcp`, `tcp4`, `tcp6`) and propagates `net.Conn` deadlines.
UDP is intentionally not silently tunneled over TCP; a future core adapter must
use AesingFlow datagram sessions explicitly.

## Generic Go core

```go
flowClient, err := aesingflow.NewClient(aesingflow.ClientConfig{
    Address: "de1.node.example:4433", TLSConfig: tlsConfig, Token: token,
})
if err != nil { /* handle */ }

outbound, err := proxy.NewDialer(proxy.DialerConfig{Client: flowClient})
if err != nil { /* handle */ }
defer outbound.Close()

conn, err := outbound.DialContext(ctx, "tcp", "example.com:443")
```

The core should use this outbound wherever it would normally use a TCP dialer.
No SOCKS listener is required for this form of integration.

## sing-box and Xray

Official sing-box and Xray binaries expose a fixed set of configuration protocol
types; adding a native `aesingflow` outbound therefore requires compiling a thin
adapter into the respective core. The adapter should only translate that core's
outbound interface to `proxy.Dialer`; TLS, token authentication, QUIC,
multiplexing, and Brutal settings stay inside AesingFlow.

For immediate use with unmodified official binaries, run
`aesingflow-proxy-client` locally and configure the core's existing SOCKS
outbound as `127.0.0.1:8010`. This is TCP-only, matching the current proxy
protocol.

Xray's architecture separates inbound and outbound proxy modules, while
sing-box's public configuration lists a fixed set of outbound types. See the
respective upstream documentation before pinning an adapter to a core version.
