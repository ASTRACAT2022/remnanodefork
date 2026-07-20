# AesingFlow SOCKS5 proxy

This directory contains a small TCP proxy over authenticated AesingFlow QUIC
streams. It adds two commands:

Build the binaries:

```sh
go build -o bin/aesingflow-proxy-server ./cmd/aesingflow-proxy-server
go build -o bin/aesingflow-proxy-client ./cmd/aesingflow-proxy-client
```

```sh
# On the server (open UDP 4433 in the firewall):
go run ./cmd/aesingflow-proxy-server \
  -listen :4433 -cert server.pem -key server-key.pem -token 'a-long-random-token'

# On macOS:
go run ./cmd/aesingflow-proxy-client \
  -server vpn.example.com:4433 -server-name vpn.example.com \
  -token 'a-long-random-token'
```

The macOS command listens on `127.0.0.1:8010` by default. Configure an
application to use SOCKS5 `127.0.0.1:8010`, or test it with:

```sh
curl --proxy socks5h://127.0.0.1:8010 https://ifconfig.me
```

Instead of specifying server and token separately, the client also accepts a
portable `aesingflow://` profile link:

```sh
go run ./cmd/aesingflow-proxy-client -link 'aesingflow://TOKEN@vpn.example.com:4433?sni=vpn.example.com#My%20server'
```

See [the link format](../docs/links.md). The link includes the access token, so
do not share it publicly.

`socks5h` sends the hostname through the tunnel, so DNS resolution happens at
the server exit. The implementation supports SOCKS5 `CONNECT` (TCP) only; it
does not implement UDP ASSOCIATE, a TUN interface, or macOS system-wide traffic
redirection. Keep the listener bound to loopback and protect the server with a
strong unique token. On macOS, proxy-aware applications can be configured with
SOCKS5 host `127.0.0.1` and port `8010`. The macOS SOCKS setting does not capture
all system traffic; a real full-device tunnel requires a separate Network
Extension/TUN client.

For a server certificate issued by a public CA such as Let's Encrypt, the macOS
client automatically uses the system trust store and needs no `-ca` argument.
For a private or self-signed server certificate, supply its public CA
certificate (never the private key): `-ca ca.pem`.

The client keeps one multiplexed QUIC connection open for all SOCKS5 requests.
Both commands allow up to 256 concurrent TCP streams by default; change this
with `-max-streams`. For high throughput on a Linux server, make sure UDP socket
buffers are not capped too low:

```sh
sysctl -w net.core.rmem_max=8388608
sysctl -w net.core.wmem_max=8388608
```

The bundled `third_party/quic-go` copy uses Hysteria-style **Brutal** by default:
a fixed-rate, paced controller for a
known dedicated link. Brutal deliberately does not reduce its target rate after
loss, so set a real ceiling instead of the NIC's theoretical speed. It is not a
general replacement for CUBIC and can make an overloaded or lossy network worse.

The ceiling applies to traffic *sent by that endpoint*. To improve downloads,
enable it on the server; to improve uploads, enable it on the macOS client. It
defaults to 250 Mbit/s, so no Brutal flags are needed. For a measured 300 Mbit/s
home connection, test this default before raising it:

```sh
# Server: controls proxy downloads to the Mac.
go run ./cmd/aesingflow-proxy-server \
  -listen :4433 -cert server.pem -key server-key.pem -token '...'

# macOS: controls proxy uploads from the Mac.
go run ./cmd/aesingflow-proxy-client \
  -server vpn.example.com:4433 -server-name vpn.example.com -token '...'
```

Use the same SOCKS5 endpoint (`127.0.0.1:8010`). The two endpoints do not need
to negotiate this setting; each only controls its own QUIC sender. Use `-cc
cubic` to opt out. `-brutal-disable-loss-compensation` is available for
experiments, but should normally remain off.

To diagnose throughput, set `QLOGDIR` before starting either command. It
records RTT, congestion-window, and packet-loss events in `.sqlog` files, but
normal runs are unchanged when `QLOGDIR` is unset:

```sh
QLOGDIR=/tmp/aesingflow-qlog go run ./cmd/aesingflow-proxy-client ...
rg -o 'recovery:packet_lost' /tmp/aesingflow-qlog | wc -l
```
