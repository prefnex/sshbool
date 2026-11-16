//! AES-256-CBC token encryption for in-app Guacamole RDP.

use aes::Aes256;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use cbc::{Decryptor, Encryptor};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::RngCore;
use serde_json::{json, Value};

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/// Per-process random keys for Guacamole connection tokens.
///
/// Tokens are minted and consumed by this same process (the local WebSocket bridge), so the
/// keys never need to leave memory. A compile-time constant would be public in an open-source
/// repository and let any local process forge or decrypt tokens (they carry RDP passwords).
struct TokenKeys {
    enc: [u8; 32],
    mac: [u8; 32],
}

fn token_keys() -> &'static TokenKeys {
    static KEYS: std::sync::OnceLock<TokenKeys> = std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        let mut enc = [0u8; 32];
        let mut mac = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut enc);
        rand::rngs::OsRng.fill_bytes(&mut mac);
        TokenKeys { enc, mac }
    })
}

fn token_mac(iv: &[u8], ciphertext: &[u8]) -> HmacSha256 {
    use hmac::Mac;
    let mut mac = HmacSha256::new_from_slice(&token_keys().mac).expect("hmac accepts any key size");
    mac.update(iv);
    mac.update(ciphertext);
    mac
}

/// Build a guacamole connection token payload for RDP over an SSH tunnel.
pub fn build_rdp_token(
    hostname: &str,
    port: u16,
    username: &str,
    password: &str,
    domain: Option<&str>,
    width: u32,
    height: u32,
    color_depth: u32,
    performance: &str,
) -> Result<String, String> {
    let (wallpaper, font_smoothing, disable_audio) = match performance {
        "lan" => ("true", "true", "false"),
        "broadband" => ("false", "true", "false"),
        "modem" => ("false", "false", "true"),
        _ => ("false", "true", "false"),
    };

    let mut settings = json!({
        "hostname": hostname,
        "port": port.to_string(),
        "username": username,
        "password": password,
        "security": "any",
        // guacd cannot pin certificates; rdp_cert::verify_or_pin pins it over the same tunnel
        // immediately before this token is minted (VULN-08).
        "ignore-cert": "true",
        "width": width,
        "height": height,
        "dpi": 96,
        "color-depth": color_depth.to_string(),
        "resize-method": "display-update",
        "enable-wallpaper": wallpaper,
        "enable-font-smoothing": font_smoothing,
        "disable-audio": disable_audio,
        "enable-drive": false,
        "create-drive-path": false,
    });

    if let Some(d) = domain.filter(|s| !s.is_empty()) {
        settings["domain"] = json!(d);
    }

    let payload = json!({
        "connection": {
            "type": "rdp",
            "settings": settings,
        }
    });

    encrypt_token(&payload)
}

/// Encrypt JSON payload (guacamole-lite compatible envelope: iv + value, both base64).
pub fn encrypt_token(payload: &Value) -> Result<String, String> {
    let plaintext = serde_json::to_string(payload).map_err(|e| e.to_string())?;

    let mut iv = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut iv);

    let cipher = Aes256CbcEnc::new_from_slices(&token_keys().enc, &iv)
        .map_err(|e| format!("cipher init: {e}"))?;
    let block_size = 16;
    let pad = block_size - (plaintext.len() % block_size);
    let mut buf = vec![0u8; plaintext.len() + pad];
    buf[..plaintext.len()].copy_from_slice(plaintext.as_bytes());
    let encrypted = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
        .map_err(|e| format!("encrypt: {e}"))?;
    let ciphertext = encrypted.to_vec();

    let tag = {
        use hmac::Mac;
        token_mac(&iv, &ciphertext).finalize().into_bytes()
    };

    let wrapper = json!({
        "iv": B64.encode(iv),
        "value": B64.encode(&ciphertext),
        "mac": B64.encode(tag),
    });

    Ok(B64.encode(serde_json::to_string(&wrapper).map_err(|e| e.to_string())?))
}

/// Decrypt token for the WebSocket bridge.
pub fn decrypt_token(encoded: &str) -> Result<Value, String> {
    let wrapper_str = B64
        .decode(encoded.trim())
        .map_err(|e| format!("base64 decode wrapper: {e}"))?;
    let wrapper: Value =
        serde_json::from_slice(&wrapper_str).map_err(|e| format!("parse wrapper: {e}"))?;

    let iv_b64 = wrapper["iv"].as_str().ok_or("missing iv")?;
    let value_b64 = wrapper["value"].as_str().ok_or("missing value")?;

    let iv = B64.decode(iv_b64).map_err(|e| format!("decode iv: {e}"))?;
    let ciphertext = B64
        .decode(value_b64)
        .map_err(|e| format!("decode value: {e}"))?;

    // Encrypt-then-MAC: reject tampered tokens before touching the CBC padding.
    let tag_b64 = wrapper["mac"].as_str().ok_or("missing mac")?;
    let tag = B64
        .decode(tag_b64)
        .map_err(|e| format!("decode mac: {e}"))?;
    {
        use hmac::Mac;
        token_mac(&iv, &ciphertext)
            .verify_slice(&tag)
            .map_err(|_| "token authentication failed".to_string())?;
    }

    let cipher = Aes256CbcDec::new_from_slices(&token_keys().enc, &iv)
        .map_err(|e| format!("cipher init: {e}"))?;
    let mut buf = ciphertext;
    let decrypted = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| format!("decrypt: {e}"))?;

    serde_json::from_slice(decrypted).map_err(|e| format!("parse payload: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_roundtrip() {
        let payload = json!({
            "connection": {
                "type": "rdp",
                "settings": {
                    "hostname": "127.0.0.1",
                    "port": "3389",
                    "username": "ubuntu",
                    "password": "secret",
                }
            }
        });
        let enc = encrypt_token(&payload).expect("encrypt");
        let dec = decrypt_token(&enc).expect("decrypt");
        assert_eq!(dec, payload);
    }

    #[test]
    fn tampered_token_is_rejected() {
        let enc = encrypt_token(&json!({ "a": 1 })).expect("encrypt");
        let raw = B64.decode(&enc).unwrap();
        let mut wrapper: Value = serde_json::from_slice(&raw).unwrap();
        let mut ct = B64.decode(wrapper["value"].as_str().unwrap()).unwrap();
        ct[0] ^= 1;
        wrapper["value"] = json!(B64.encode(&ct));
        let forged = B64.encode(serde_json::to_string(&wrapper).unwrap());
        assert!(decrypt_token(&forged).is_err());
    }

    #[test]
    fn token_without_mac_is_rejected() {
        let enc = encrypt_token(&json!({ "a": 1 })).expect("encrypt");
        let raw = B64.decode(&enc).unwrap();
        let mut wrapper: Value = serde_json::from_slice(&raw).unwrap();
        wrapper.as_object_mut().unwrap().remove("mac");
        let forged = B64.encode(serde_json::to_string(&wrapper).unwrap());
        assert!(decrypt_token(&forged).is_err());
    }

    #[test]
    fn build_rdp_token_has_required_fields() {
        let token = build_rdp_token(
            "127.0.0.1",
            3389,
            "ubuntu",
            "pass",
            None,
            1280,
            720,
            32,
            "auto",
        )
        .expect("build");
        let dec = decrypt_token(&token).expect("decrypt");
        let settings = &dec["connection"]["settings"];
        assert_eq!(settings["hostname"], "127.0.0.1");
        assert_eq!(settings["password"], "pass");
        assert_eq!(settings["color-depth"], "32");
    }
}
