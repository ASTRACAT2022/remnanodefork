# Modern uTLS Fingerprints

This fork resolves TLS fingerprints through one registry in `transport/internet/tls`.
Both regular TLS and REALITY use the same `tls.GetFingerprint` entrypoint, so every
supported name below is available to both paths unless a transport explicitly rejects
standard Go TLS aliases such as `unsafe`.

## uTLS Version

The dependency is pinned to the latest stable tag available from the Go module proxy
at the time of this change:

```text
github.com/refraction-networking/utls v1.8.2
```

The previous pseudo-version was removed from `go.mod` and `go.sum`.

## Supported Names

| Name | uTLS ClientHelloID | Notes |
| --- | --- | --- |
| `chrome`, `chrome_auto` | `HelloChrome_Auto` | Resolves to Chrome 133 in uTLS v1.8.2. |
| `chrome_120` | `HelloChrome_120` | Exact supported profile. |
| `chrome_124` | `HelloChrome_120` | Closest supported profile in uTLS v1.8.2. |
| `chrome_126` | `HelloChrome_120` | Closest supported profile in uTLS v1.8.2. |
| `chrome_128` | `HelloChrome_131` | Closest supported profile in uTLS v1.8.2. |
| `chrome_131` | `HelloChrome_131` | Exact supported profile. |
| `chrome_133` | `HelloChrome_133` | Exact supported profile. |
| `firefox`, `firefox_auto` | `HelloFirefox_Auto` | Resolves to Firefox 120 in uTLS v1.8.2. |
| `firefox_120` | `HelloFirefox_120` | Exact supported profile. |
| `firefox_125` | `HelloFirefox_120` | Closest supported profile in uTLS v1.8.2. |
| `safari`, `safari_auto` | `HelloSafari_Auto` | Resolves to Safari 16.0 in uTLS v1.8.2. |
| `safari_16_0` | `HelloSafari_16_0` | Exact supported profile. |
| `ios` | `HelloIOS_Auto` | Resolves to iOS 14 in uTLS v1.8.2. |
| `android` | `HelloAndroid_11_OkHttp` | Android OkHttp profile. |
| `edge` | `HelloEdge_Auto` | Resolves to Edge 85 in uTLS v1.8.2. |
| `yandex`, `yandex_auto` | `HelloChrome_Auto` | Yandex Browser has no dedicated uTLS profile, so Chromium-compatible Chrome is used. |
| `random` | process-selected browser profile | Selected once at process startup and reused. |
| `randomized` | `HelloRandomizedALPN` with fixed seed | Seeded once at process startup and reused. |
| `randomizednoalpn` | `HelloRandomizedNoALPN` with fixed seed | Seeded once at process startup and reused. |

Legacy `hello*` uTLS names are still accepted for compatibility with existing configs.

## Vanilla Client Compatibility

Clients do not need new link parameters for this fork. Standard values such as
`fp=chrome` continue to work and resolve to the best Chromium profile bundled with
the pinned uTLS version.

The resolver also normalizes common GUI/export variants before validation:

- case, spaces, dots, and dashes: `Chrome-133`, `chrome 133`, `chrome.133`
- compact legacy names: `HelloChrome133`
- explicit legacy names: `hello-chrome-133`
- Chromium-family aliases: `brave`, `chromium`, `google chrome`, `opera`, `vivaldi`
- Yandex aliases: `yandex`, `yandex-browser`, `YaBrowser`

Future browser version labels are mapped to the closest supported profile available
in this build instead of forcing users to edit imported links. For example,
`chrome_134` currently resolves to `chrome_133`.

## Behavior

`chrome_auto`, `firefox_auto`, and `safari_auto` are process-stable aliases to the
current stable uTLS presets. They do not generate a new ClientHello per connection.

`random` chooses one entry from the browser profile pool at process startup and keeps
that choice until restart.

`randomized` and `randomizednoalpn` create one seeded `ClientHelloID` at process
startup. The seed is reused for later connections, avoiding per-connection churn.

At debug log level, resolved aliases include the requested and selected profile names.

## Limits

TLS ClientHello fingerprinting does not make the upper protocol look like a browser.
For example, ALPN and HTTP/2 behavior still need to match the transport actually in
use. A JA3-like value is only one view of ClientHello and does not describe all TLS
extensions, extension contents, record behavior, or application traffic.

## TCP REALITY Vision Under DPI

This fork also supports disabling VLESS Vision direct-copy with:

```text
XRAY_VLESS_VISION_DIRECT_COPY=false
```

Direct-copy is faster, but after the first TLS records it turns Vision traffic into
a long raw TCP copy path. Some DPI deployments allow the REALITY handshake and then
kill sustained video-like streams. Disabling direct-copy keeps Vision on its padded
copy path for the whole connection. Client links do not need to change.

## REALITY Handshake Burst Limiter

For client-side networks that freeze after several fresh REALITY handshakes to the
same server/SNI, this fork can pace handshakes with:

```text
XRAY_REALITY_HANDSHAKE_MAX_PER_WINDOW=3
XRAY_REALITY_HANDSHAKE_WINDOW_MS=60000
XRAY_REALITY_HANDSHAKE_MIN_INTERVAL_MS=0
```

The limiter is off by default. It only changes timing before new TCP REALITY dials;
links and server config stay the same. Use it to test whether failures are caused
by burst fingerprinting rather than server-side throughput.
