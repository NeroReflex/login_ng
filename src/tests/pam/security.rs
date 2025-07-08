/*
    login-ng A greeter written in rust that also supports autologin with systemd-homed
    Copyright (C) 2024-2025  Denis Benato

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

use crate::pam::security::{SessionPrelude, SessionPreludeError};
use crate::rsa::pkcs1::EncodeRsaPublicKey;
use rand::rngs::OsRng;
use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs8::LineEnding, RsaPrivateKey, RsaPublicKey};
use std::sync::Arc;

const RSA_PRIVATE_KEY: &str = r#"
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
"#;

#[test]
fn test_new() {
    let pub_key_pem = RSA_PRIVATE_KEY;
    let session = SessionPrelude::new(pub_key_pem.to_string());

    assert_eq!(session.one_time_token().len(), 255);
}

#[test]
fn test_encrypt_decrypt_success() {
    let priv_key = Arc::new(RsaPrivateKey::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap());
    let pub_key = RsaPublicKey::from(priv_key.as_ref());

    let pub_key_pem = pub_key.to_pkcs1_pem(LineEnding::CRLF).unwrap();

    let session = SessionPrelude::new(pub_key_pem.to_string());
    let plaintext = "Hello, World!";

    let encrypted = session
        .encrypt(plaintext.to_string())
        .expect("Encryption failed");

    let (otp, decrypted_plaintext) =
        SessionPrelude::decrypt(priv_key.clone(), encrypted).expect("Decryption failed");

    assert_eq!(otp.len(), 255);
    assert_eq!(decrypted_plaintext, plaintext.as_bytes());
}

#[test]
fn test_encrypt_too_long_plaintext() {
    let priv_key = RsaPrivateKey::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
    let pub_key = RsaPublicKey::from(priv_key);

    let pub_key_pem = pub_key.to_pkcs1_pem(LineEnding::CRLF).unwrap();
    let session = SessionPrelude::new(pub_key_pem.to_string());
    let long_plaintext = "A".repeat(256); // 256 characters long

    let result = session.encrypt(long_plaintext);
    assert!(result.is_err());
    assert_eq!(result.err(), Some(SessionPreludeError::PlaintextTooLong));
}

#[test]
fn test_decrypt_invalid_ciphertext() {
    let priv_key = RsaPrivateKey::new(&mut OsRng, 2048).expect("Failed to generate private key");
    let priv_key_arc = Arc::new(priv_key);

    let invalid_ciphertext = vec![0; 10]; // Invalid ciphertext

    let result = SessionPrelude::decrypt(priv_key_arc.clone(), invalid_ciphertext);
    assert!(result.is_err());
    assert_eq!(result.err(), Some(SessionPreludeError::InvalidCiphertext));
}
