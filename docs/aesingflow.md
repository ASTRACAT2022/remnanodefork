# AesingFlow outbound

This Node image includes a native Xray outbound named `aesingflow`. It creates
one multiplexed AesingFlow QUIC connection per outbound profile and carries
TCP CONNECT streams through it.

```json
{
  "protocol": "aesingflow",
  "tag": "aesingflow-de1",
  "settings": {
    "server": "de1.node.example",
    "serverPort": 4433,
    "token": "replace-with-secret-token",
    "tls": {
      "serverName": "de1.node.example",
      "caFile": "/etc/ssl/certs/aesingflow-private-ca.pem"
    },
    "maxStreams": 256,
    "brutalBps": 250000000
  }
}
```

`tls.serverName` defaults to `server` for a hostname. It is required when
`server` is an IP address. TLS 1.3 certificate verification is always enabled;
there is intentionally no insecure mode. Omit `caFile` when the certificate is
issued by a public CA; otherwise provide a file containing only the public PEM
certificate for the private CA.

The outbound accepts TCP only. Xray requests for UDP return an explicit
unsupported-protocol error and are never silently routed outside AesingFlow.
`brutalBps` is the client-side send ceiling in bit/s; zero uses AesingFlow's
default. Set `disableBrutal` to `true` to use CUBIC instead.

See the [AesingFlow core integration manual](https://github.com/ASTRACAT2022/AesingFlow/blob/main/docs/core-integration-manual.md)
for operational and verification guidance.
