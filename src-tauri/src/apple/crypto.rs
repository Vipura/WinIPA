// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use crate::errors::WinIpaError;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use sha2::Sha256;

#[derive(Debug, Clone)]
pub struct GeneratedKeyPair {
    pub private_key_pem: String,
    pub csr_pem: String,
}

/// Simple DER encoder helper functions.
fn der_encode_len(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else if len <= 0xFFFF {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    } else {
        vec![
            0x83,
            (len >> 16) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    }
}

fn der_tag_and_len(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_encode_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_sequence(content: &[u8]) -> Vec<u8> {
    der_tag_and_len(0x30, content)
}

fn der_set(content: &[u8]) -> Vec<u8> {
    der_tag_and_len(0x31, content)
}

fn der_oid(oid_bytes: &[u8]) -> Vec<u8> {
    der_tag_and_len(0x06, oid_bytes)
}

fn der_utf8_string(s: &str) -> Vec<u8> {
    der_tag_and_len(0x0c, s.as_bytes())
}

fn der_bit_string(data: &[u8]) -> Vec<u8> {
    let mut content = vec![0x00]; // 0 unused bits
    content.extend_from_slice(data);
    der_tag_and_len(0x03, &content)
}

/// Builds an X.509 Name structure (e.g. CN=<common_name>, OU=<team_id>).
fn build_subject_name(common_name: &str, team_id: &str) -> Vec<u8> {
    // 2.5.4.3 = id-at-commonName (OID: 55 04 03)
    let cn_oid = [0x55, 0x04, 0x03];
    let cn_attr = der_sequence(&[der_oid(&cn_oid), der_utf8_string(common_name)].concat());
    let cn_rdn = der_set(&cn_attr);

    // 2.5.4.11 = id-at-organizationalUnitName (OID: 55 04 0B)
    let ou_oid = [0x55, 0x04, 0x0b];
    let ou_attr = der_sequence(&[der_oid(&ou_oid), der_utf8_string(team_id)].concat());
    let ou_rdn = der_set(&ou_attr);

    // 2.5.4.6 = id-at-countryName = "US" (OID: 55 04 06)
    let c_oid = [0x55, 0x04, 0x06];
    let c_val = der_tag_and_len(0x13, b"US"); // PrintableString "US"
    let c_attr = der_sequence(&[der_oid(&c_oid), c_val].concat());
    let c_rdn = der_set(&c_attr);

    der_sequence(&[cn_rdn, ou_rdn, c_rdn].concat())
}

/// Builds the SubjectPublicKeyInfo structure for an RSA public key.
fn build_subject_pk_info(pkcs1_public_key_der: &[u8]) -> Vec<u8> {
    // OID: 1.2.840.113549.1.1.1 = rsaEncryption (2A 86 48 86 F7 0D 01 01 01)
    let rsa_oid = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    let null = [0x05, 0x00];
    let alg_id = der_sequence(&[der_oid(&rsa_oid), null.to_vec()].concat());

    let bit_str = der_bit_string(pkcs1_public_key_der);
    der_sequence(&[alg_id, bit_str].concat())
}

/// Builds the sha256WithRSAEncryption AlgorithmIdentifier.
fn build_sha256_rsa_alg() -> Vec<u8> {
    // OID: 1.2.840.113549.1.1.11 = sha256WithRSAEncryption (2A 86 48 86 F7 0D 01 01 0B)
    let sha256_rsa_oid = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    let null = [0x05, 0x00];
    der_sequence(&[der_oid(&sha256_rsa_oid), null.to_vec()].concat())
}

/// Generates a 2048-bit RSA keypair and a PKCS#10 Certificate Signing Request (CSR)
/// formatted as standard PEM strings for Apple Developer certificate issuance.
pub fn generate_dev_csr(common_name: &str, team_id: &str) -> Result<GeneratedKeyPair, WinIpaError> {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| WinIpaError::CertificateFailed(format!("Failed to generate RSA key: {e}")))?;

    // Export private key as PKCS#8 PEM
    let private_key_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| WinIpaError::CertificateFailed(format!("Failed to encode private key: {e}")))?
        .to_string();

    // Export public key in PKCS#1 DER format
    let public_key = private_key.to_public_key();
    let pkcs1_der = public_key
        .to_pkcs1_der()
        .map_err(|e| WinIpaError::CertificateFailed(format!("Failed to encode public key: {e}")))?;

    // Build CertificationRequestInfo DER
    let version = vec![0x02, 0x01, 0x00]; // INTEGER 0
    let subject = build_subject_name(common_name, team_id);
    let pk_info = build_subject_pk_info(pkcs1_der.as_bytes());
    let attributes = vec![0xa0, 0x00]; // [0] IMPLICIT empty attributes

    let mut cri_content = Vec::new();
    cri_content.extend(version);
    cri_content.extend(subject);
    cri_content.extend(pk_info);
    cri_content.extend(attributes);

    let cri_der = der_sequence(&cri_content);

    // Sign CertificationRequestInfo with private key (SHA-256 + RSA PKCS#1 v1.5)
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign(&cri_der);

    let sig_alg = build_sha256_rsa_alg();
    let sig_bit_str = der_bit_string(&signature.to_bytes());

    // Assemble final CertificationRequest SEQUENCE
    let csr_der = der_sequence(&[cri_der, sig_alg, sig_bit_str].concat());

    // Wrap in standard PEM formatting
    let b64 = base64_encode(&csr_der);
    let mut csr_pem = String::from("-----BEGIN CERTIFICATE REQUEST-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        csr_pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        csr_pem.push('\n');
    }
    csr_pem.push_str("-----END CERTIFICATE REQUEST-----\n");

    Ok(GeneratedKeyPair {
        private_key_pem,
        csr_pem,
    })
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);

    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };

        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);

        result.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        result.push(ALPHABET[((n >> 12) & 63) as usize] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((n >> 6) & 63) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[(n & 63) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_dev_csr_produces_valid_pem() {
        let kp = generate_dev_csr("Apple Development: John Doe", "TEAM123456")
            .expect("CSR generation should succeed");

        assert!(kp
            .private_key_pem
            .starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(kp
            .csr_pem
            .starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        assert!(kp.csr_pem.ends_with("-----END CERTIFICATE REQUEST-----\n"));
    }
}
