use std::pin::Pin;

use huskarl_core::{
    crypto::verifier::{BoxedJwsVerifier, CreateVerifierError, JwsVerifierPlatform},
    jwk,
    platform::MaybeSendFuture,
};

/// A verifier factory that takes public JWK material and returns a [`BoxedJwsVerifier`].
///
/// The returned verifier is implemented in `WebCrypto`.
#[derive(Debug, Clone, Copy, Default)]
pub struct WebCryptoVerifierPlatform;

impl JwsVerifierPlatform for WebCryptoVerifierPlatform {
    fn create_verifier_from_jwk(
        &self,
        jwk: jwk::PublicJwk,
    ) -> Pin<Box<dyn MaybeSendFuture<Output = Result<BoxedJwsVerifier, CreateVerifierError>>>> {
        Box::pin(async {
            let key = crate::asymmetric::verifier::AsymmetricPublicKey::from_jwk(jwk);
            key.await
                .map_or(Err(CreateVerifierError::UnsupportedKey), |k| {
                    Ok(BoxedJwsVerifier::new(k))
                })
        })
    }
}
