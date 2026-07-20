# Security model

TLS 1.3 authenticates the server and encrypts QUIC traffic. Client TLS verification is never disabled by default: callers must provide a normal `tls.Config` with trusted roots and an appropriate server name. Token authentication is an application authorization check, not a substitute for TLS.

* A passive observer sees encrypted QUIC metadata but cannot read AesingFlow controls or data.
* An active MITM is rejected by TLS certificate validation unless the caller deliberately installs a trusted interception CA.
* Malicious clients face bounded control frames, sessions, datagram payloads, queues, authentication attempts and nonce storage.
* Token comparison uses `subtle.ConstantTimeCompare`; tokens and payloads are never logged.
* Authentication has a bounded timestamp window and a single-use client nonce cache to mitigate replay. A compromised valid token remains valid until expiry/revocation in the configured authenticator; rotation is the operational mitigation.
* Version/capability negotiation rejects major-version downgrade and unknown mandatory capabilities.
* QUIC address validation and anti-amplification are provided by quic-go. The application sends no data before TLS/QUIC establishment and successful authentication.

Padding changes only control-frame length inside TLS. It is disabled by default, capped by configuration, and is not cover traffic or protocol impersonation.
