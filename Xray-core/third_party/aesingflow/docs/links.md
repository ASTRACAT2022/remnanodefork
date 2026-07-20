# `aesingflow://` profile links

An AesingFlow TCP client profile can be shared as a portable link:

```text
aesingflow://TOKEN@de1.node.example:4433?sni=de1.node.example#My%20AesingFlow
```

The token is a credential. Treat a link like a password: do not publish it and
rotate the token if it is exposed.

## Fields

| Part | Meaning |
| --- | --- |
| `TOKEN` | Required access token, URL-encoded as needed. |
| `host:port` | Required AesingFlow QUIC server address. |
| `sni` | Optional TLS server name. Defaults to the host. |
| `cc=cubic` | Optional opt-out from default Brutal. Brutal is otherwise used. |
| `brutal_bps` | Optional Brutal outbound rate in bits/s. The default is 250000000. |
| `max_streams` | Optional maximum concurrent TCP streams. |
| `#name` | Optional human-readable profile name. |

TLS certificate verification is always on. A private CA certificate is a local
trust decision and is therefore supplied with `-ca`, never embedded in a link.

## Create and use a link

```sh
go run ./cmd/aesingflow-link \
  -server de1.node.example:4433 -server-name de1.node.example \
  -token 'replace-with-token' -name 'My AesingFlow'

go run ./cmd/aesingflow-proxy-client \
  -link 'aesingflow://TOKEN@de1.node.example:4433?sni=de1.node.example#My%20AesingFlow'
```

`-link` overrides the connection fields (`-server`, `-token`, `-server-name`,
`-cc`, `-brutal-bps`, and `-max-streams`). Local listener and trust options such
as `-listen` and `-ca` remain independent.
