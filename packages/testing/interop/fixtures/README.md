# Synthetic interoperability TLS fixtures — TEST ONLY

All private keys here are intentionally public. Never install this CA or reuse these
keys outside local synthetic tests. No production identity or federation is implied.

- `ca.pem`, `ca-key.pem`: trusted synthetic CA and its key.
- `server.pem`, `server-key.pem`: server certificate/key, SANs `localhost` and `127.0.0.1`, serverAuth EKU.
- `client.pem`, `client-key.pem`: trusted client certificate/key, clientAuth EKU.
- `untrusted-client.pem`, `untrusted-client-key.pem`: client certificate/key signed by a separate CA.
- `untrusted-ca.pem`: separate CA certificate; **do not add it to the server trust store**.

Run `sh generate.sh` from any directory to regenerate using OpenSSL. Certificates
use RSA-2048/SHA-256 and 36,500-day validity from generation. The untrusted CA key
is temporary and discarded. Regeneration replaces fixture keys and certificates.
The auth module's fixed token clock is unrelated to TLS's real certificate clock.
