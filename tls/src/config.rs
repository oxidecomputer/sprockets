// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Construction of the rustls configurations underlying a sprockets
//! connection.
//!
//! The functions here are pure: they read the key and certificate material
//! named by a [`SprocketsConfig`](crate::keys::SprocketsConfig) and return a
//! rustls configuration. They open no sockets and perform no handshake, which
//! is what lets a single pair of builders serve every transport.

use crate::keys::{CertResolver, ResolveSetting, RotCertVerifier};
use crate::{crypto_provider, load_root_cert, Error};
use camino::Utf8PathBuf;
use rustls::{
    client::{danger::ServerCertVerifier, ResolvesClientCert},
    server::{danger::ClientCertVerifier, ResolvesServerCert},
    version::TLS13,
    ClientConfig, ServerConfig,
};
use std::sync::Arc;
use x509_cert::Certificate;

/// Loads the PEM-encoded root certificates at each of `paths`.
///
/// # Errors
///
/// Returns [`Error::FailedRead`] naming the offending path if any root cannot
/// be read, and [`Error::Der`] or [`Error::Pem`] if one cannot be parsed. A
/// single unusable root fails the whole load: sprockets has no notion of a
/// partially trusted set.
pub(crate) fn load_roots(
    paths: &[Utf8PathBuf],
) -> Result<Vec<Certificate>, Error> {
    paths.iter().map(load_root_cert).collect()
}

/// Builds the client-side TLS configuration for a sprockets connection.
///
/// The client authenticates the server with a [`RotCertVerifier`] over `roots`
/// and presents its own trust quorum credentials from `resolve`. The
/// configuration pins TLS 1.3 and the [`crypto_provider`] suite list.
pub(crate) fn new_tls_client_config(
    resolve: ResolveSetting,
    roots: Vec<Certificate>,
    log: &slog::Logger,
) -> Result<ClientConfig, Error> {
    let verifier = Arc::new(RotCertVerifier::new(roots, log.clone())?)
        as Arc<dyn ServerCertVerifier>;

    let client_resolver = Arc::new(CertResolver::new(log.clone(), resolve))
        as Arc<dyn ResolvesClientCert>;

    Ok(
        ClientConfig::builder_with_provider(Arc::new(crypto_provider()))
            .with_protocol_versions(&[&TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_cert_resolver(client_resolver),
    )
}

/// Builds the server-side TLS configuration for a sprockets connection.
///
/// Mutual authentication is mandatory: the [`RotCertVerifier`] installed over
/// `roots` is a [`ClientCertVerifier`] whose
/// [`client_auth_mandatory`](ClientCertVerifier::client_auth_mandatory) is
/// `true`, so a client that presents no certificate never completes the
/// handshake.
pub(crate) fn new_tls_server_config(
    resolve: ResolveSetting,
    roots: Vec<Certificate>,
    log: &slog::Logger,
) -> Result<ServerConfig, Error> {
    let verifier = Arc::new(RotCertVerifier::new(roots, log.clone())?)
        as Arc<dyn ClientCertVerifier>;

    let server_resolver = Arc::new(CertResolver::new(log.clone(), resolve))
        as Arc<dyn ResolvesServerCert>;

    Ok(
        ServerConfig::builder_with_provider(Arc::new(crypto_provider()))
            .with_protocol_versions(&[&TLS13])?
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(server_resolver),
    )
}
