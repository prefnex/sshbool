-- 0021_rdp_known_certs.sql
-- VULN-08: trust-on-first-use pins for RDP server TLS certificates.
-- Keyed by the SSH host the tunnel runs through plus the RDP target behind it.
CREATE TABLE IF NOT EXISTS rdp_known_certs (
    host_id TEXT NOT NULL,
    target TEXT NOT NULL,
    port INTEGER NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    PRIMARY KEY (host_id, target, port)
);
