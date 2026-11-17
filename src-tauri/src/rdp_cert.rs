//! RDP server certificate pinning (VULN-08).
//!
//! guacd only offers `ignore-cert` on/off and RDP servers (xRDP, Windows) almost always present
//! self-signed certificates, so strict CA validation would break every connection. Instead we
//! fetch the server certificate ourselves through the same SSH tunnel right before the client
//! connects and pin its SHA-256 fingerprint (trust-on-first-use):
//!
//! * first connection: the fingerprint is stored silently, so auto-login keeps working;
//! * same fingerprint later: connect as usual;
//! * different fingerprint: refuse until the user explicitly trusts the new certificate.
//!
//! The password is never involved here: the probe stops right after the TLS handshake.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::AppError;

/// Prefix used in mismatch errors so the UI can offer "trust new certificate".
pub const MISMATCH_TAG: &str = "RDP_CERT_MISMATCH";

const PROTOCOL_RDP: u32 = 0;
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

/// X.224 Connection Request carrying an RDP_NEG_REQ for TLS | CredSSP.
fn connection_request() -> [u8; 19] {
    [
        0x03, 0x00, 0x00, 0x13, // TPKT, length 19
        0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 CR TPDU
        0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, // RDP_NEG_REQ: SSL | HYBRID
    ]
}

/// Outcome of reading the server's X.224 Connection Confirm.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Negotiation {
    /// Server selected TLS or CredSSP (both start with a TLS handshake).
    Tls,
    /// Server only speaks legacy RDP security — no certificate to pin.
    StandardRdp,
}

/// Parse the Connection Confirm PDU (TPKT + X.224 CC + optional RDP_NEG_RSP/FAILURE).
pub(crate) fn parse_connection_confirm(pdu: &[u8]) -> Result<Negotiation, String> {
    if pdu.len() < 11 || pdu[0] != 0x03 {
        return Err("not an RDP server (bad TPKT header)".into());
    }
    if pdu[5] & 0xf0 != 0xd0 {
        return Err("unexpected X.224 response".into());
    }
    let neg = &pdu[11..];
    if neg.len() < 8 {
        // Pre-negotiation server: legacy RDP security only.
        return Ok(Negotiation::StandardRdp);
    }
    let value = u32::from_le_bytes([neg[4], neg[5], neg[6], neg[7]]);
    match neg[0] {
        0x02 if value == PROTOCOL_RDP => Ok(Negotiation::StandardRdp),
        0x02 => Ok(Negotiation::Tls),
        // RDP_NEG_FAILURE: server refuses TLS/CredSSP, so it can only do standard security.
        0x03 => Ok(Negotiation::StandardRdp),
        other => Err(format!("unknown negotiation type {other:#x}")),
    }
}

/// Upper-case hex SHA-256 of a DER certificate, colon separated (matches `openssl -fingerprint`).
pub(crate) fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Accepts any certificate chain (we pin the leaf manually) but still verifies the handshake
/// signatures, so the peer must hold the private key for the certificate it presented.
#[derive(Debug)]
struct PinCapture {
    provider: Arc<rustls::crypto::CryptoProvider>,
    leaf: std::sync::Mutex<Option<Vec<u8>>>,
}

impl ServerCertVerifier for PinCapture {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Ok(mut slot) = self.leaf.lock() {
            *slot = Some(end_entity.as_ref().to_vec());
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Fetch the RDP server's leaf certificate through `127.0.0.1:local_port` (the SSH tunnel).
/// Returns `Ok(None)` when the server only supports legacy RDP security.
pub async fn fetch_certificate(local_port: u16) -> Result<Option<Vec<u8>>, String> {
    tokio::time::timeout(PROBE_TIMEOUT, fetch_certificate_inner(local_port))
        .await
        .map_err(|_| "timed out reading the RDP server certificate".to_string())?
}

async fn fetch_certificate_inner(local_port: u16) -> Result<Option<Vec<u8>>, String> {
    let mut stream = TcpStream::connect(("127.0.0.1", local_port))
        .await
        .map_err(|e| format!("connect to RDP tunnel: {e}"))?;
    stream
        .write_all(&connection_request())
        .await
        .map_err(|e| format!("send X.224 request: {e}"))?;

    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| format!("read X.224 confirm: {e}"))?;
    let len = u16::from_be_bytes([header[2], header[3]]) as usize;
    if !(11..=512).contains(&len) {
        return Err(format!("unexpected X.224 confirm length {len}"));
    }
    let mut pdu = header.to_vec();
    pdu.resize(len, 0);
    stream
        .read_exact(&mut pdu[4..])
        .await
        .map_err(|e| format!("read X.224 confirm: {e}"))?;

    if parse_connection_confirm(&pdu)? == Negotiation::StandardRdp {
        return Ok(None);
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinCapture {
        provider: provider.clone(),
        leaf: std::sync::Mutex::new(None),
    });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls config: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name =
        ServerName::try_from("rdp.sshbool.invalid").map_err(|e| format!("server name: {e}"))?;
    let mut tls = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| format!("TLS handshake with RDP server: {e}"))?;
    let _ = tls.shutdown().await;

    let leaf = verifier.leaf.lock().ok().and_then(|mut s| s.take());
    leaf.map(Some)
        .ok_or_else(|| "RDP server did not present a certificate".to_string())
}

/// What the pin store decided for a freshly observed fingerprint.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PinDecision {
    FirstUse,
    Match,
    Mismatch { expected: String },
}

pub(crate) fn decide(stored: Option<&str>, observed: &str) -> PinDecision {
    match stored {
        None => PinDecision::FirstUse,
        Some(s) if s.eq_ignore_ascii_case(observed) => PinDecision::Match,
        Some(s) => PinDecision::Mismatch {
            expected: s.to_string(),
        },
    }
}

async fn stored_fingerprint(
    pool: &SqlitePool,
    host_id: &str,
    target: &str,
    port: u16,
) -> Result<Option<String>, AppError> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT fingerprint_sha256 FROM rdp_known_certs WHERE host_id = ? AND target = ? AND port = ?",
    )
    .bind(host_id)
    .bind(target)
    .bind(port as i64)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::Internal {
        message: format!("rdp cert lookup: {e}"),
    })?;
    Ok(row.map(|r| r.0))
}

/// Verify (or pin on first use) the RDP certificate behind an active SSH tunnel.
///
/// Never prompts: first use is trusted automatically so auto-login is unaffected. Only a
/// *changed* certificate — or a probe failure on a host that already has a pin — blocks.
pub async fn verify_or_pin(
    pool: &SqlitePool,
    host_id: &str,
    target: &str,
    port: u16,
    local_port: u16,
) -> Result<(), AppError> {
    let stored = stored_fingerprint(pool, host_id, target, port).await?;
    let der = match fetch_certificate(local_port).await {
        Ok(Some(der)) => der,
        Ok(None) => {
            if stored.is_some() {
                return Err(AppError::Validation {
                    field: "rdpCertificate".into(),
                    message: format!(
                        "{MISMATCH_TAG}: {target}:{port} previously used TLS but now only offers \
                         legacy RDP security. This can indicate a downgrade attack."
                    ),
                });
            }
            tracing::warn!(
                "RDP: {target}:{port} only supports legacy RDP security; no certificate to pin"
            );
            return Ok(());
        }
        Err(e) if stored.is_some() => {
            return Err(AppError::Connection {
                message: format!("Could not verify the pinned RDP certificate: {e}"),
                retryable: true,
            });
        }
        Err(e) => {
            // Nothing pinned yet (e.g. TLS 1.0-only server): behave as before rather than
            // breaking the connection, but leave a trace.
            tracing::warn!("RDP: certificate probe failed for {target}:{port}: {e}");
            return Ok(());
        }
    };

    let observed = fingerprint(&der);
    let now = chrono::Utc::now().timestamp_millis();
    match decide(stored.as_deref(), &observed) {
        PinDecision::FirstUse => {
            sqlx::query(
                "INSERT OR REPLACE INTO rdp_known_certs (host_id, target, port, fingerprint_sha256, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(host_id)
            .bind(target)
            .bind(port as i64)
            .bind(&observed)
            .bind(now)
            .bind(now)
            .execute(pool)
            .await
            .map_err(|e| AppError::Internal {
                message: format!("rdp cert pin: {e}"),
            })?;
            tracing::info!("RDP: pinned certificate for {target}:{port} (SHA256 {observed})");
            Ok(())
        }
        PinDecision::Match => {
            let _ = sqlx::query(
                "UPDATE rdp_known_certs SET last_seen = ? WHERE host_id = ? AND target = ? AND port = ?",
            )
            .bind(now)
            .bind(host_id)
            .bind(target)
            .bind(port as i64)
            .execute(pool)
            .await;
            Ok(())
        }
        PinDecision::Mismatch { expected } => Err(AppError::Validation {
            field: "rdpCertificate".into(),
            message: format!(
                "{MISMATCH_TAG}: the RDP certificate for {target}:{port} changed.\n\
                 Expected SHA256 {expected}\nReceived SHA256 {observed}\n\
                 If the server was reinstalled or its certificate renewed, trust the new one."
            ),
        }),
    }
}

/// Forget a pinned certificate so the next connection pins the current one.
pub async fn forget(
    pool: &SqlitePool,
    host_id: &str,
    target: &str,
    port: u16,
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM rdp_known_certs WHERE host_id = ? AND target = ? AND port = ?")
        .bind(host_id)
        .bind(target)
        .bind(port as i64)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal {
            message: format!("rdp cert forget: {e}"),
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn confirm(neg: &[u8]) -> Vec<u8> {
        let len = 11 + neg.len();
        let mut v = vec![0x03, 0x00, 0x00, len as u8, 0x06 + neg.len() as u8, 0xd0];
        v.extend_from_slice(&[0, 0, 0, 0, 0]);
        v.extend_from_slice(neg);
        v
    }

    #[test]
    fn request_is_well_formed() {
        let req = connection_request();
        assert_eq!(u16::from_be_bytes([req[2], req[3]]) as usize, req.len());
        assert_eq!(req[4] as usize, req.len() - 5);
    }

    #[test]
    fn parses_tls_and_hybrid_selection() {
        assert_eq!(
            parse_connection_confirm(&confirm(&[2, 0, 8, 0, 1, 0, 0, 0])),
            Ok(Negotiation::Tls)
        );
        assert_eq!(
            parse_connection_confirm(&confirm(&[2, 0, 8, 0, 2, 0, 0, 0])),
            Ok(Negotiation::Tls)
        );
    }

    #[test]
    fn parses_legacy_security() {
        assert_eq!(
            parse_connection_confirm(&confirm(&[2, 0, 8, 0, 0, 0, 0, 0])),
            Ok(Negotiation::StandardRdp)
        );
        assert_eq!(
            parse_connection_confirm(&confirm(&[3, 0, 8, 0, 2, 0, 0, 0])),
            Ok(Negotiation::StandardRdp)
        );
        assert_eq!(
            parse_connection_confirm(&confirm(&[])),
            Ok(Negotiation::StandardRdp)
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_connection_confirm(b"SSH-2.0-OpenSSH_9.6\r\n").is_err());
    }

    #[test]
    fn fingerprint_format() {
        let fp = fingerprint(b"abc");
        assert!(fp.starts_with("BA:78:16:BF"));
        assert_eq!(fp.split(':').count(), 32);
    }

    /// Minimal fake RDP server: answers the X.224 request selecting TLS, then serves `cert`.
    async fn fake_rdp_server(cert_pem: &'static str, key_pem: &'static str) -> u16 {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::PrivateKeyDer;

        let certs = vec![CertificateDer::from_pem_slice(cert_pem.as_bytes()).unwrap()];
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let mut req = [0u8; 19];
                    sock.read_exact(&mut req).await.unwrap();
                    let cc = confirm(&[2, 0, 8, 0, 1, 0, 0, 0]);
                    sock.write_all(&cc).await.unwrap();
                    let _ = acceptor.accept(sock).await;
                });
            }
        });
        port
    }

    const CERT1: &str = include_str!("../tests/fixtures/rdp_test_cert.crt");
    const KEY1: &str = include_str!("../tests/fixtures/rdp_test_key.key");
    const CERT2: &str = include_str!("../tests/fixtures/rdp_test_cert2.crt");
    const KEY2: &str = include_str!("../tests/fixtures/rdp_test_key2.key");

    #[tokio::test]
    async fn fetches_certificate_over_x224_and_tls() {
        let port = fake_rdp_server(CERT1, KEY1).await;
        let der = fetch_certificate(port).await.unwrap().expect("tls cert");
        // Same value as `openssl x509 -noout -fingerprint -sha256` on the fixture.
        assert_eq!(
            fingerprint(&der),
            "C6:41:85:2B:78:30:E2:F0:87:91:89:3C:CD:B5:82:F0:BA:B1:1F:1C:22:24:F3:35:1D:86:26:A5:37:9F:60:06"
        );
    }

    #[tokio::test]
    async fn pins_on_first_use_and_blocks_a_changed_certificate() {
        let dir = std::env::temp_dir().join(format!("sshbool-rdpcert-{}", uuid::Uuid::now_v7()));
        let pool = infrastructure::db::open_pool(&dir.join("t.db"))
            .await
            .unwrap();
        infrastructure::db::migrate(&pool).await.unwrap();

        let good = fake_rdp_server(CERT1, KEY1).await;
        let evil = fake_rdp_server(CERT2, KEY2).await;

        // First use: silently pinned (auto-login is not interrupted).
        verify_or_pin(&pool, "host-1", "127.0.0.1", 3389, good)
            .await
            .unwrap();
        // Same certificate again: fine.
        verify_or_pin(&pool, "host-1", "127.0.0.1", 3389, good)
            .await
            .unwrap();
        // Different certificate for the same target: refused.
        let err = verify_or_pin(&pool, "host-1", "127.0.0.1", 3389, evil)
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains(MISMATCH_TAG));
        // Another target is independent.
        verify_or_pin(&pool, "host-1", "10.0.0.5", 3389, evil)
            .await
            .unwrap();
        // After the user explicitly trusts the new certificate it is accepted.
        forget(&pool, "host-1", "127.0.0.1", 3389).await.unwrap();
        verify_or_pin(&pool, "host-1", "127.0.0.1", 3389, evil)
            .await
            .unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn pin_decisions() {
        assert_eq!(decide(None, "AA"), PinDecision::FirstUse);
        assert_eq!(decide(Some("aa"), "AA"), PinDecision::Match);
        assert_eq!(
            decide(Some("BB"), "AA"),
            PinDecision::Mismatch {
                expected: "BB".into()
            }
        );
    }
}
