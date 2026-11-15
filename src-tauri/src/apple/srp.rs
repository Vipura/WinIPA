// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

use crate::errors::WinIpaError;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use num_bigint::BigUint;
use rand::RngCore;
use sha2::{Digest, Sha256};

const N_HEX: &str = "AC6BDB41324AFA59462360144C6A0B4613C2F03980EE4BA77E42FCD57A67F392\
FB6B7B3B8FBF6D729D27E633E75A4E0FACB102E7CEF772C440E63071E56370B1\
782A0524E4D78964722ADD214A0450654AC24E1B0721BEB5FA739E0C4318E202\
DF609EF30FD9AE0A1CB623E71C334752BD3FE8A2DB9DA14EC83E8251F5F2F97C\
6DA4366EC14E04BBAF42DECBB5E454F6F5030F043DF4BBAC64E86EEF23B4E08E\
2397227E1DF89CE631E074C4CA23713CA53A5CA07AB6B7C18D659DCD271A41FD\
83429533F43ED72E063B52D36FA8026E2E0224644A4A9EB80A8C1936024308DA\
461563B32C145B1E0E384D44B80A84B2FE124E10E3B77E56D54082266C7F6B271407";

const G_VAL: u32 = 2;

fn get_n() -> BigUint {
    let bytes = hex::decode(N_HEX).expect("Valid N_HEX constant");
    BigUint::from_bytes_be(&bytes)
}

fn pad_256(slice: &[u8]) -> [u8; 256] {
    let mut out = [0u8; 256];
    if slice.len() >= 256 {
        out.copy_from_slice(&slice[slice.len() - 256..]);
    } else {
        out[256 - slice.len()..].copy_from_slice(slice);
    }
    out
}

fn biguint_to_256(b: &BigUint) -> [u8; 256] {
    let bytes = b.to_bytes_be();
    pad_256(&bytes)
}

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn compute_k(n: &BigUint) -> BigUint {
    let n_bytes = biguint_to_256(n);
    let g_bytes = pad_256(&[G_VAL as u8]);
    let mut combined = [0u8; 512];
    combined[..256].copy_from_slice(&n_bytes);
    combined[256..].copy_from_slice(&g_bytes);
    let hash = sha256_hash(&combined);
    BigUint::from_bytes_be(&hash)
}

pub struct AppleSrpClient {
    a: BigUint,
    a_pub: BigUint,
}

impl AppleSrpClient {
    /// Generates client ephemeral `a` and computes public `A = g^a mod N`.
    /// Returns `(client_instance, base64_encoded_A)`.
    pub fn new() -> (Self, String) {
        let n = get_n();
        let g = BigUint::from(G_VAL);

        let mut rng = rand::thread_rng();
        let mut a_bytes = [0u8; 32];
        rng.fill_bytes(&mut a_bytes);
        let a = BigUint::from_bytes_be(&a_bytes);

        let a_pub = g.modpow(&a, &n);
        let a_pub_bytes = biguint_to_256(&a_pub);
        let a_pub_b64 = BASE64.encode(a_pub_bytes);

        (Self { a, a_pub }, a_pub_b64)
    }

    /// Computes the SRP cryptographic proofs `M1` and `M2` given server challenge parameters.
    pub fn compute_proofs(
        &self,
        account_name: &str,
        password: &str,
        salt: &[u8],
        iterations: u32,
        protocol: &str,
        b_bytes: &[u8],
    ) -> Result<(String, String), WinIpaError> {
        let n = get_n();
        let g = BigUint::from(G_VAL);
        let zero = BigUint::from(0u32);

        let b = BigUint::from_bytes_be(b_bytes);
        if &b % &n == zero {
            return Err(WinIpaError::AppleAuthFailed(
                "Invalid SRP server public key: B mod N is zero".into(),
            ));
        }

        let a_bytes = biguint_to_256(&self.a_pub);
        let b_padded = pad_256(b_bytes);

        // u = SHA256(PAD(A) | PAD(B))
        let mut u_input = [0u8; 512];
        u_input[..256].copy_from_slice(&a_bytes);
        u_input[256..].copy_from_slice(&b_padded);
        let u_hash = sha256_hash(&u_input);
        let u = BigUint::from_bytes_be(&u_hash);

        if u == zero {
            return Err(WinIpaError::AppleAuthFailed(
                "Invalid SRP scrambling parameter u is zero".into(),
            ));
        }

        // Password key derivation via PBKDF2
        let pass_digest = if protocol == "s2k_fo" {
            let p_hash = sha256_hash(password.as_bytes());
            hex::encode(p_hash).into_bytes()
        } else {
            sha256_hash(password.as_bytes()).to_vec()
        };

        let mut derived = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(&pass_digest, salt, iterations, &mut derived);
        let x = BigUint::from_bytes_be(&derived);

        // k = SHA256(PAD(N) | PAD(g))
        let k = compute_k(&n);

        // base = (B - k * (g^x mod N)) mod N
        let gx = g.modpow(&x, &n);
        let kgx = (&k * &gx) % &n;
        let base = if b >= kgx {
            (&b - &kgx) % &n
        } else {
            let diff = (&kgx - &b) % &n;
            if diff == zero {
                zero.clone()
            } else {
                &n - diff
            }
        };

        // exp = a + u * x
        let exp = &self.a + (&u * &x);

        // S = base^exp mod N
        let s = base.modpow(&exp, &n);
        let s_bytes = biguint_to_256(&s);

        // Session Key K = SHA256(PAD(S))
        let k_bytes = sha256_hash(&s_bytes);

        // H(N) xor H(g)
        let hn = sha256_hash(&biguint_to_256(&n));
        let hg = sha256_hash(&pad_256(&[G_VAL as u8]));
        let mut h_xor = [0u8; 32];
        for i in 0..32 {
            h_xor[i] = hn[i] ^ hg[i];
        }

        // H(username)
        let h_user = sha256_hash(account_name.as_bytes());

        // M1 = SHA256(H_xor | H_user | salt | PAD(A) | PAD(B) | K)
        let mut m1_hasher = Sha256::new();
        m1_hasher.update(h_xor);
        m1_hasher.update(h_user);
        m1_hasher.update(salt);
        m1_hasher.update(a_bytes);
        m1_hasher.update(b_padded);
        m1_hasher.update(k_bytes);
        let m1_digest = m1_hasher.finalize();

        // M2 = SHA256(PAD(A) | M1 | K)
        let mut m2_hasher = Sha256::new();
        m2_hasher.update(a_bytes);
        m2_hasher.update(m1_digest);
        m2_hasher.update(k_bytes);
        let m2_digest = m2_hasher.finalize();

        let m1_b64 = BASE64.encode(m1_digest);
        let m2_b64 = BASE64.encode(m2_digest);

        Ok((m1_b64, m2_b64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srp_client_creation_produces_valid_a() {
        let (client, a_b64) = AppleSrpClient::new();
        assert!(!a_b64.is_empty());
        assert_eq!(a_b64.len(), 344); // 256 bytes base64 encoded is 344 chars
        assert!(client.a > BigUint::from(0u32));
        assert!(client.a_pub > BigUint::from(0u32));
    }

    #[test]
    fn test_srp_proof_generation() {
        let (client, _) = AppleSrpClient::new();
        let salt = BASE64.decode("Oo+F4kYAof4xodKOQGh6GA==").unwrap();
        let b_bytes = [1u8; 256];
        let res = client.compute_proofs(
            "test@example.com",
            "password123",
            &salt,
            821,
            "s2k_fo",
            &b_bytes,
        );
        assert!(res.is_ok());
        let (m1, m2) = res.unwrap();
        assert!(!m1.is_empty());
        assert!(!m2.is_empty());
    }

    #[test]
    fn test_pbkdf2_derivation_parity() {
        let salt = BASE64.decode("Oo+F4kYAof4xodKOQGh6GA==").unwrap();
        let pass_digest = hex::encode(sha256_hash(b"wrongpassword")).into_bytes();
        let mut derived = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(&pass_digest, &salt, 821, &mut derived);
        assert_eq!(
            hex::encode(derived),
            "5f8c2c6a64900a8b25d4687541e9429c3ea94cdbf854e3045578a0c480255d2c"
        );
    }
}
