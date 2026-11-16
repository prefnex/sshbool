//! Server-side VNC authentication for the in-app noVNC bridge (VULN-16).
//!
//! Previously the decrypted vault password was returned to the webview so noVNC could answer
//! the VNC challenge. The bridge now sits in the middle of the RFB handshake:
//!
//! ```text
//! noVNC  <— WebSocket —>  bridge  <— SSH tunnel —>  VNC server
//!          offers "None"          answers VNC-auth (DES challenge)
//! ```
//!
//! When no password is known, or the server does not offer VNC authentication, the handshake
//! is forwarded unchanged and noVNC behaves exactly as before.

use futures_util::{SinkExt, Stream, StreamExt};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

const SEC_INVALID: u8 = 0;
const SEC_NONE: u8 = 1;
const SEC_VNC_AUTH: u8 = 2;

/// 256-bit random URL-safe token for the bridge WebSocket.
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Constant-time token comparison.
pub fn tokens_match(presented: &str, expected: &str) -> bool {
    let (a, b) = (presented.as_bytes(), expected.as_bytes());
    if a.len() != b.len() || a.is_empty() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Answer a VNC authentication challenge (DES with bit-reversed password bytes).
pub fn vnc_auth_response(password: &str, challenge: &[u8; 16]) -> [u8; 16] {
    use des::cipher::{BlockCipherEncrypt, KeyInit};

    let mut key = [0u8; 8];
    for (slot, byte) in key.iter_mut().zip(password.as_bytes()) {
        *slot = byte.reverse_bits();
    }
    let cipher = des::Des::new(&key.into());
    let mut out = [0u8; 16];
    for (i, chunk) in challenge.chunks_exact(8).enumerate() {
        let mut block = des::cipher::Block::<des::Des>::default();
        block.copy_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        out[i * 8..i * 8 + 8].copy_from_slice(&block);
    }
    key.iter_mut().for_each(|b| *b = 0);
    out
}

/// RFB minor version agreed with the client (3.3, 3.7 or 3.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rfb {
    V3_3,
    V3_7,
    V3_8,
}

pub(crate) fn parse_version(v: &[u8; 12]) -> Result<Rfb, String> {
    if &v[..4] != b"RFB " || v[11] != b'\n' {
        return Err("not an RFB server".into());
    }
    let text = std::str::from_utf8(&v[4..11]).map_err(|_| "bad RFB version".to_string())?;
    let (major, minor) = text.split_once('.').ok_or("bad RFB version")?;
    let major: u32 = major.parse().map_err(|_| "bad RFB version")?;
    let minor: u32 = minor.parse().map_err(|_| "bad RFB version")?;
    Ok(match (major, minor) {
        (3, 3) | (3, 4) | (3, 5) | (3, 6) => Rfb::V3_3,
        (3, 7) => Rfb::V3_7,
        _ => Rfb::V3_8,
    })
}

/// Buffered byte reader over the binary messages of a WebSocket.
pub struct WsReader<S> {
    inner: S,
    buf: Vec<u8>,
}

impl<S> WsReader<S>
where
    S: Stream<Item = Result<Message, WsError>> + Unpin,
{
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            buf: Vec::new(),
        }
    }

    pub async fn read_exact(&mut self, n: usize) -> Result<Vec<u8>, String> {
        while self.buf.len() < n {
            match self.inner.next().await {
                Some(Ok(Message::Binary(data))) => self.buf.extend_from_slice(&data),
                Some(Ok(Message::Close(_))) | None => return Err("client closed".into()),
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(format!("websocket: {e}")),
            }
        }
        Ok(self.buf.drain(..n).collect())
    }

    pub fn take_buffered(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

async fn send<W>(ws: &mut W, bytes: &[u8]) -> Result<(), String>
where
    W: futures_util::Sink<Message, Error = WsError> + Unpin,
{
    ws.send(Message::Binary(bytes.to_vec().into()))
        .await
        .map_err(|e| format!("websocket send: {e}"))
}

async fn read_n<R: AsyncRead + Unpin>(r: &mut R, n: usize) -> Result<Vec<u8>, String> {
    let mut v = vec![0u8; n];
    r.read_exact(&mut v)
        .await
        .map_err(|e| format!("vnc read: {e}"))?;
    Ok(v)
}

async fn read_u32<R: AsyncRead + Unpin>(r: &mut R) -> Result<u32, String> {
    let v = read_n(r, 4).await?;
    Ok(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
}

async fn write_all<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> Result<(), String> {
    w.write_all(bytes)
        .await
        .map_err(|e| format!("vnc write: {e}"))
}

/// Read a server failure reason (u32 length + text) and forward it to the client.
async fn relay_reason<R, W>(server: &mut R, client: &mut W) -> Result<String, String>
where
    R: AsyncRead + Unpin,
    W: futures_util::Sink<Message, Error = WsError> + Unpin,
{
    let len = read_u32(server).await? as usize;
    let reason = read_n(server, len.min(4096)).await?;
    let mut frame = (reason.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&reason);
    send(client, &frame).await?;
    Ok(String::from_utf8_lossy(&reason).into_owned())
}

/// Perform the RFB handshake up to (not including) ClientInit.
///
/// On return the connection is in a state where both sides can be piped verbatim.
pub async fn handshake<S, W, R, T>(
    client_rx: &mut WsReader<S>,
    client_tx: &mut W,
    server_rx: &mut R,
    server_tx: &mut T,
    password: Option<&str>,
) -> Result<(), String>
where
    S: Stream<Item = Result<Message, WsError>> + Unpin,
    W: futures_util::Sink<Message, Error = WsError> + Unpin,
    R: AsyncRead + Unpin,
    T: AsyncWrite + Unpin,
{
    // 1. ProtocolVersion: server -> client, client's choice -> server.
    let server_version = read_n(server_rx, 12).await?;
    send(client_tx, &server_version).await?;
    let client_version = client_rx.read_exact(12).await?;
    write_all(server_tx, &client_version).await?;
    let mut cv = [0u8; 12];
    cv.copy_from_slice(&client_version);
    let version = parse_version(&cv)?;

    let password = password.filter(|p| !p.is_empty());

    // 2. Security negotiation.
    if version == Rfb::V3_3 {
        let sec = read_u32(server_rx).await?;
        if sec == SEC_INVALID as u32 {
            send(client_tx, &sec.to_be_bytes()).await?;
            let reason = relay_reason(server_rx, client_tx).await?;
            return Err(format!("server refused connection: {reason}"));
        }
        match password {
            Some(pw) if sec == SEC_VNC_AUTH as u32 => {
                answer_challenge(server_rx, server_tx, pw).await?;
                check_result(server_rx).await?;
                // 3.3 "None" has no SecurityResult, so the client goes straight to ClientInit.
                send(client_tx, &(SEC_NONE as u32).to_be_bytes()).await?;
            }
            _ => send(client_tx, &sec.to_be_bytes()).await?,
        }
        return Ok(());
    }

    let count = read_n(server_rx, 1).await?[0];
    if count == 0 {
        send(client_tx, &[0]).await?;
        let reason = relay_reason(server_rx, client_tx).await?;
        return Err(format!("server refused connection: {reason}"));
    }
    let types = read_n(server_rx, count as usize).await?;

    let Some(pw) = password.filter(|_| types.contains(&SEC_VNC_AUTH)) else {
        // Nothing for us to do: forward the offer and let noVNC handle security itself.
        let mut offer = vec![count];
        offer.extend_from_slice(&types);
        send(client_tx, &offer).await?;
        return Ok(());
    };

    // Offer only "None" to the browser; answer the real challenge here.
    send(client_tx, &[1, SEC_NONE]).await?;
    let chosen = client_rx.read_exact(1).await?[0];
    if chosen != SEC_NONE {
        return Err(format!("client chose unexpected security type {chosen}"));
    }
    write_all(server_tx, &[SEC_VNC_AUTH]).await?;
    answer_challenge(server_rx, server_tx, pw).await?;

    let result = read_u32(server_rx).await?;
    if result != 0 {
        if version == Rfb::V3_8 {
            send(client_tx, &result.to_be_bytes()).await?;
            let reason = relay_reason(server_rx, client_tx).await?;
            return Err(format!("VNC authentication failed: {reason}"));
        }
        return Err("VNC authentication failed (wrong password?)".into());
    }
    // 3.8 sends SecurityResult for "None" too; 3.7 does not.
    if version == Rfb::V3_8 {
        send(client_tx, &0u32.to_be_bytes()).await?;
    }
    Ok(())
}

async fn answer_challenge<R, T>(
    server_rx: &mut R,
    server_tx: &mut T,
    pw: &str,
) -> Result<(), String>
where
    R: AsyncRead + Unpin,
    T: AsyncWrite + Unpin,
{
    let challenge = read_n(server_rx, 16).await?;
    let mut c = [0u8; 16];
    c.copy_from_slice(&challenge);
    let response = vnc_auth_response(pw, &c);
    write_all(server_tx, &response).await
}

async fn check_result<R: AsyncRead + Unpin>(server_rx: &mut R) -> Result<(), String> {
    match read_u32(server_rx).await? {
        0 => Ok(()),
        _ => Err("VNC authentication failed (wrong password?)".into()),
    }
}

#[cfg(test)]
#[allow(clippy::result_large_err)]
mod tests {
    use super::*;
    use futures_util::stream;

    #[test]
    fn des_matches_reference_vector() {
        // Reference computed independently with
        // `openssl enc -des-ecb -K 0E86CECEEEF64E26 -nopad` (bit-reversed "password", zero block).
        let resp = vnc_auth_response("password", &[0u8; 16]);
        assert_eq!(hex::encode(&resp[..8]), hex::encode(&resp[8..]));
        assert_eq!(hex::encode(&resp[..8]), REFERENCE_PASSWORD_ZERO_BLOCK);
    }

    const REFERENCE_PASSWORD_ZERO_BLOCK: &str = "ff97502e9422f089";

    #[test]
    fn version_parsing() {
        assert_eq!(parse_version(b"RFB 003.008\n"), Ok(Rfb::V3_8));
        assert_eq!(parse_version(b"RFB 003.007\n"), Ok(Rfb::V3_7));
        assert_eq!(parse_version(b"RFB 003.003\n"), Ok(Rfb::V3_3));
        assert_eq!(parse_version(b"RFB 003.889\n"), Ok(Rfb::V3_8));
        assert!(parse_version(b"SSH-2.0-xxxx").is_err());
    }

    #[test]
    fn token_compare() {
        let t = random_token();
        assert_eq!(t.len(), 64);
        assert!(tokens_match(&t, &t.clone()));
        assert!(!tokens_match("", ""));
        assert!(!tokens_match(&t[..63], &t));
        assert!(!tokens_match(&random_token(), &t));
    }

    fn client(
        frames: Vec<Vec<u8>>,
    ) -> WsReader<impl Stream<Item = Result<Message, WsError>> + Unpin> {
        WsReader::new(stream::iter(
            frames
                .into_iter()
                .map(|f| Ok(Message::Binary(f.into())))
                .collect::<Vec<_>>(),
        ))
    }

    fn sink() -> impl futures_util::Sink<Message, Error = WsError> + Unpin {
        futures_util::sink::drain().sink_map_err(|e: std::convert::Infallible| match e {})
    }

    #[tokio::test]
    async fn v38_vnc_auth_is_answered_by_bridge() {
        let mut server_to_bridge = b"RFB 003.008\n".to_vec();
        server_to_bridge.extend_from_slice(&[2, SEC_VNC_AUTH, 16]); // offers VNC auth + others
        server_to_bridge.extend_from_slice(&[7u8; 16]); // challenge
        server_to_bridge.extend_from_slice(&0u32.to_be_bytes()); // OK
        let mut server_rx = std::io::Cursor::new(server_to_bridge);
        let mut server_tx: Vec<u8> = Vec::new();

        // Client split its messages arbitrarily: version in two frames, then choice + ClientInit.
        let mut rx = client(vec![
            b"RFB 003".to_vec(),
            b".008\n".to_vec(),
            vec![SEC_NONE, 1],
        ]);
        let mut tx = sink();
        handshake(
            &mut rx,
            &mut tx,
            &mut server_rx,
            &mut server_tx,
            Some("secret"),
        )
        .await
        .expect("handshake");

        let mut expected = b"RFB 003.008\n".to_vec();
        expected.push(SEC_VNC_AUTH);
        expected.extend_from_slice(&vnc_auth_response("secret", &[7u8; 16]));
        assert_eq!(server_tx, expected);
        // ClientInit (shared flag) stays buffered for the pipe.
        assert_eq!(rx.take_buffered(), vec![1]);
    }

    #[tokio::test]
    async fn without_password_offer_is_forwarded() {
        let mut server_to_bridge = b"RFB 003.008\n".to_vec();
        server_to_bridge.extend_from_slice(&[1, SEC_VNC_AUTH]);
        let mut server_rx = std::io::Cursor::new(server_to_bridge);
        let mut server_tx: Vec<u8> = Vec::new();
        let mut rx = client(vec![b"RFB 003.008\n".to_vec()]);
        let mut tx = sink();
        handshake(&mut rx, &mut tx, &mut server_rx, &mut server_tx, None)
            .await
            .expect("handshake");
        // Bridge only relayed the version; the security choice is left to noVNC.
        assert_eq!(server_tx, b"RFB 003.008\n".to_vec());
    }

    #[tokio::test]
    async fn wrong_password_fails() {
        let mut server_to_bridge = b"RFB 003.008\n".to_vec();
        server_to_bridge.extend_from_slice(&[1, SEC_VNC_AUTH]);
        server_to_bridge.extend_from_slice(&[0u8; 16]);
        server_to_bridge.extend_from_slice(&1u32.to_be_bytes());
        server_to_bridge.extend_from_slice(&4u32.to_be_bytes());
        server_to_bridge.extend_from_slice(b"nope");
        let mut server_rx = std::io::Cursor::new(server_to_bridge);
        let mut server_tx: Vec<u8> = Vec::new();
        let mut rx = client(vec![b"RFB 003.008\n".to_vec(), vec![SEC_NONE]]);
        let mut tx = sink();
        let err = handshake(&mut rx, &mut tx, &mut server_rx, &mut server_tx, Some("x"))
            .await
            .unwrap_err();
        assert!(err.contains("nope"));
    }

    #[tokio::test]
    async fn v33_vnc_auth() {
        let mut server_to_bridge = b"RFB 003.003\n".to_vec();
        server_to_bridge.extend_from_slice(&(SEC_VNC_AUTH as u32).to_be_bytes());
        server_to_bridge.extend_from_slice(&[9u8; 16]);
        server_to_bridge.extend_from_slice(&0u32.to_be_bytes());
        let mut server_rx = std::io::Cursor::new(server_to_bridge);
        let mut server_tx: Vec<u8> = Vec::new();
        let mut rx = client(vec![b"RFB 003.003\n".to_vec()]);
        let mut tx = sink();
        handshake(&mut rx, &mut tx, &mut server_rx, &mut server_tx, Some("pw"))
            .await
            .expect("handshake");
        let mut expected = b"RFB 003.003\n".to_vec();
        expected.extend_from_slice(&vnc_auth_response("pw", &[9u8; 16]));
        assert_eq!(server_tx, expected);
    }
}
