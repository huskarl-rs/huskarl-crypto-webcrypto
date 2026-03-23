//! Implements JWS signing keys on WASM using the WebCrypto/Subtle API.
//!
//! Currently, the following JWS algorithms are available:
//!
//! - Asymmetric (NIST elliptic curves)
//!   - ES256
//!   - ES384
//! - Asymmetric (RSA)
//!   - RS256
//!   - RS384
//!   - RS512
//!   - PS256
//!   - PS384
//!   - PS512
//! - Asymmetric (`EdDSA`)
//!   - `Ed25519` (aka `EdDSA`)

use serde::Serialize;
use snafu::prelude::*;
use std::borrow::Cow;
use std::sync::Arc;

use web_sys::CryptoKey;

use huskarl_core::{
    crypto::signer::{HasPublicKey, JwsSigningKey, SigningKeyMetadata},
    jwk,
};

use crate::{
    KeyUsage,
    helpers::{
        self, AsymmetricKeyGenParams, GetCryptoError, JsSignError, SignAlgorithm,
        generate_asymmetric_key, get_crypto, get_public_jwk, sign_with_key,
    },
};

#[derive(Debug)]
struct PrivateKeyInner {
    crypto_key: CryptoKey,
    algorithm: AsymmetricAlgorithm,
    key_metadata: SigningKeyMetadata,
    jwk: jwk::PublicJwk,
}

/// A non-exportable asymmetric private key used to create JWS signatures.
///
/// Keys used here are not extractable by JavaScript.
#[derive(Debug, Clone)]
pub struct PrivateKey {
    inner: Arc<PrivateKeyInner>,
}

/// Algorithm supported by this key.
#[derive(Debug, Serialize, Clone, Copy)]
pub enum AsymmetricAlgorithm {
    /// ES256
    Es256,
    /// ES384
    Es384,
    /// RS256
    Rs256 {
        /// Modulus length in bits.
        ///
        /// Traditionally 2048, but 3072 is a common recommendation, and some systems require 4096.
        ///
        /// The computational cost grows polynomially with modulus length, while the security gain
        /// is sub-linear — doubling the modulus size does not double the security.
        modulus_length: u32,
    },
    /// RS384
    Rs384 {
        /// Modulus length in bits.
        ///
        /// Traditionally 2048, but 3072 is a common recommendation, and some systems require 4096.
        ///
        /// The computational cost grows polynomially with modulus length, while the security gain
        /// is sub-linear — doubling the modulus size does not double the security.
        modulus_length: u32,
    },
    /// RS512
    Rs512 {
        /// Modulus length in bits.
        ///
        /// Traditionally 2048, but 3072 is a common recommendation, and some systems require 4096.
        ///
        /// The computational cost grows polynomially with modulus length, while the security gain
        /// is sub-linear — doubling the modulus size does not double the security.
        modulus_length: u32,
    },
    /// PS256
    Ps256 {
        /// Modulus length in bits.
        ///
        /// Traditionally 2048, but 3072 is a common recommendation, and some systems require 4096.
        ///
        /// The computational cost grows polynomially with modulus length, while the security gain
        /// is sub-linear — doubling the modulus size does not double the security.
        modulus_length: u32,
    },
    /// PS384
    Ps384 {
        /// Modulus length in bits.
        ///
        /// Traditionally 2048, but 3072 is a common recommendation, and some systems require 4096.
        ///
        /// The computational cost grows polynomially with modulus length, while the security gain
        /// is sub-linear — doubling the modulus size does not double the security.
        modulus_length: u32,
    },
    /// PS512
    Ps512 {
        /// Modulus length in bits.
        ///
        /// Traditionally 2048, but 3072 is a common recommendation, and some systems require 4096.
        ///
        /// The computational cost grows polynomially with modulus length, while the security gain
        /// is sub-linear — doubling the modulus size does not double the security.
        modulus_length: u32,
    },
    /// `EdDSA` (polymorphic algorithm name)
    EdDSA,
    /// Ed25519 (fully specified algorithm name, ref. RFC 9864)
    Ed25519,
}

impl AsymmetricAlgorithm {
    fn key_gen_params(&self) -> AsymmetricKeyGenParams<'_> {
        match self {
            AsymmetricAlgorithm::Es256 => AsymmetricKeyGenParams::Ec {
                name: "ECDSA",
                named_curve: "P-256",
            },
            AsymmetricAlgorithm::Es384 => AsymmetricKeyGenParams::Ec {
                name: "ECDSA",
                named_curve: "P-384",
            },
            AsymmetricAlgorithm::Rs256 { modulus_length } => AsymmetricKeyGenParams::RsaHashed {
                name: "RSASSA-PKCS1-v1_5",
                modulus_length: *modulus_length,
                public_exponent: &[0x01, 0x00, 0x01],
                hash: "SHA-256",
            },
            AsymmetricAlgorithm::Rs384 { modulus_length } => AsymmetricKeyGenParams::RsaHashed {
                name: "RSASSA-PKCS1-v1_5",
                modulus_length: *modulus_length,
                public_exponent: &[0x01, 0x00, 0x01],
                hash: "SHA-384",
            },
            AsymmetricAlgorithm::Rs512 { modulus_length } => AsymmetricKeyGenParams::RsaHashed {
                name: "RSASSA-PKCS1-v1_5",
                modulus_length: *modulus_length,
                public_exponent: &[0x01, 0x00, 0x01],
                hash: "SHA-512",
            },
            AsymmetricAlgorithm::Ps256 { modulus_length } => AsymmetricKeyGenParams::RsaHashed {
                name: "RSA-PSS",
                modulus_length: *modulus_length,
                public_exponent: &[0x01, 0x00, 0x01],
                hash: "SHA-256",
            },
            AsymmetricAlgorithm::Ps384 { modulus_length } => AsymmetricKeyGenParams::RsaHashed {
                name: "RSA-PSS",
                modulus_length: *modulus_length,
                public_exponent: &[0x01, 0x00, 0x01],
                hash: "SHA-384",
            },
            AsymmetricAlgorithm::Ps512 { modulus_length } => AsymmetricKeyGenParams::RsaHashed {
                name: "RSA-PSS",
                modulus_length: *modulus_length,
                public_exponent: &[0x01, 0x00, 0x01],
                hash: "SHA-512",
            },
            AsymmetricAlgorithm::EdDSA | AsymmetricAlgorithm::Ed25519 => {
                AsymmetricKeyGenParams::Ed25519
            }
        }
    }

    fn sign_algorithm(&self) -> SignAlgorithm<'_> {
        match self {
            Self::Es256 => SignAlgorithm::EcDsa {
                name: "ECDSA",
                hash: "SHA-256",
            },
            Self::Es384 => SignAlgorithm::EcDsa {
                name: "ECDSA",
                hash: "SHA-384",
            },
            Self::Rs256 { .. } | Self::Rs384 { .. } | Self::Rs512 { .. } => SignAlgorithm::RsaPkcs1,
            Self::Ps256 { .. } => SignAlgorithm::RsaPss {
                name: "RSA-PSS",
                salt_length: 32,
            },
            Self::Ps384 { .. } => SignAlgorithm::RsaPss {
                name: "RSA-PSS",
                salt_length: 48,
            },
            Self::Ps512 { .. } => SignAlgorithm::RsaPss {
                name: "RSA-PSS",
                salt_length: 64,
            },
            Self::EdDSA | Self::Ed25519 => SignAlgorithm::Ed25519,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::Rs256 { .. } => "RS256",
            Self::Rs384 { .. } => "RS384",
            Self::Rs512 { .. } => "RS512",
            Self::Ps256 { .. } => "PS256",
            Self::Ps384 { .. } => "PS384",
            Self::Ps512 { .. } => "PS512",
            Self::EdDSA => "EdDSA",
            Self::Ed25519 => "Ed25519",
        }
    }
}

/// Errors that can occur when generating a private key.
#[derive(Debug, Snafu)]
pub enum GenerateError {
    /// Unable to find webcrypto support in environment.
    #[snafu(display("Failed to find WebCrypto support"))]
    NoCrypto {
        /// The underlying error.
        source: GetCryptoError,
    },
    /// An error occurred when attempting to generate the key.
    #[snafu(display("Error generating key"))]
    Generate {
        /// The underlying error.
        source: helpers::GenerateKeyError,
    },
    /// An error occurred when attempting to get the JWK for the key.
    #[snafu(display("Error getting JWK for private key"))]
    GetPublicJwk {
        /// The underlying error.
        source: helpers::GetPublicJwkError,
    },
}

impl PrivateKey {
    /// Creates a non-extractable private key which can sign material using the specified JWS algorithm.
    ///
    /// # Errors
    ///
    /// May return an error if this key type is not supported, or there were
    /// issues getting the corresponding public key information for the private key.
    pub async fn generate(algorithm: AsymmetricAlgorithm) -> Result<Self, GenerateError> {
        let crypto = get_crypto().context(NoCryptoSnafu)?;

        let key_pair = generate_asymmetric_key(
            &crypto.subtle(),
            algorithm.key_gen_params(),
            &[KeyUsage::Sign],
        )
        .await
        .context(GenerateSnafu)?;

        let public_key_jwk = get_public_jwk(&crypto.subtle(), &key_pair.get_public_key())
            .await
            .context(GetPublicJwkSnafu)?;

        Ok(Self {
            inner: Arc::new(PrivateKeyInner {
                crypto_key: key_pair.get_private_key(),
                algorithm,
                key_metadata: SigningKeyMetadata {
                    jws_algorithm: algorithm.name().to_string(),
                    key_id: public_key_jwk.kid.clone(),
                },
                jwk: public_key_jwk,
            }),
        })
    }
}

/// Errors that can occur when signing.
#[derive(Debug, Snafu)]
pub enum SignError {
    /// Unable to find webcrypto support in environment.
    #[snafu(
        context(name(CryptoAbsentSnafu)),
        display("Failed to find WebCrypto support")
    )]
    NoCrypto {
        /// The underlying error.
        source: GetCryptoError,
    },
    /// Error occurred when attempting to sign.
    #[snafu(display("Signing failed"))]
    Sign {
        /// The underlying error.
        source: JsSignError,
    },
}

impl huskarl_core::Error for SignError {
    fn is_retryable(&self) -> bool {
        false
    }
}

impl JwsSigningKey for PrivateKey {
    type Error = SignError;

    fn key_metadata(&self) -> Cow<'_, SigningKeyMetadata> {
        Cow::Borrowed(&self.inner.key_metadata)
    }

    async fn sign_unchecked(&self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let crypto = get_crypto().context(CryptoAbsentSnafu)?;

        sign_with_key(
            &crypto.subtle(),
            self.inner.algorithm.sign_algorithm(),
            &self.inner.crypto_key,
            input,
        )
        .await
        .context(SignSnafu)
    }
}

impl HasPublicKey for PrivateKey {
    fn public_key_jwk(&self) -> &jwk::PublicJwk {
        &self.inner.jwk
    }
}
