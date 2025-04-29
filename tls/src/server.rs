// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A TLS based server

use crate::keys::{
    CertResolver, ResolveSetting, RotCertVerifier, SprocketsConfig,
};
use crate::{crypto_provider, load_root_cert};
use crate::{Error, Stream};
use camino::Utf8PathBuf;
use rustls::{
    server::{
        danger::{ClientCertVerified, ClientCertVerifier},
        ResolvesServerCert,
    },
    version::TLS13,
    CipherSuite, ServerConfig, SignatureScheme,
};
use slog::error;
use std::net::SocketAddrV6;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use x509_cert::Certificate;

impl ResolvesServerCert for CertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        // We only support Ed25519 and we control both sides of the connection
        if !client_hello
            .signature_schemes()
            .iter()
            .all(|&s| s == SignatureScheme::ED25519)
        {
            error!(
                self.log,
                "Invalid signature scheme(s) in client hello message: {:?}",
                client_hello.signature_schemes()
            );
            return None;
        }

        // We only want to allow `TLS13_CHACHA20_POLY1305_SHA256`
        // from the client, but rustls automatically inserts
        // `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` into the `ClientHello`. Therefore
        // we filter before checking for our desired algorithm.
        if !client_hello
            .cipher_suites()
            .iter()
            .filter(|&&s| s != CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
            .all(|&s| s == CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)
        {
            error!(
                self.log,
                "Invalid cipher suite(s) in client hello message: {:?}",
                client_hello.cipher_suites()
            );
            return None;
        }

        match self.load_certified_key() {
            Ok(key) => Some(key),
            Err(e) => {
                error!(self.log, "failed to load certified key: {e}");
                None
            }
        }
    }
}

impl ClientCertVerifier for RotCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    // We explicitly ignore the timestamp since we may be operating before the
    // rack has proper time.
    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.verify_cert(end_entity, intermediates)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        self.verify_signature(message, cert, dss.signature())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

pub struct Server {
    _log: slog::Logger,
    tcp_listener: TcpListener,
    tls_acceptor: TlsAcceptor,
}

impl Server {
    fn new_tls_local_server_config(
        priv_key: Utf8PathBuf,
        cert_chain: Utf8PathBuf,
        roots: Vec<Utf8PathBuf>,
        log: slog::Logger,
    ) -> Result<ServerConfig, Error> {
        let roots = roots
            .into_iter()
            .map(|x| load_root_cert(&x))
            .collect::<Result<Vec<Certificate>, _>>()?;

        let verifier = Arc::new(RotCertVerifier::new(roots, log.clone())?)
            as Arc<dyn ClientCertVerifier>;

        let server_resolver = Arc::new(CertResolver::new(
            log.clone(),
            ResolveSetting::Local {
                priv_key,
                cert_chain,
            },
        )) as Arc<dyn ResolvesServerCert>;

        let config =
            ServerConfig::builder_with_provider(Arc::new(crypto_provider()))
                .with_protocol_versions(&[&TLS13])?
                .with_client_cert_verifier(verifier)
                .with_cert_resolver(server_resolver);

        Ok(config)
    }

    fn new_tls_ipcc_server_config(
        roots: Vec<Utf8PathBuf>,
        log: slog::Logger,
    ) -> Result<ServerConfig, Error> {
        let roots = roots
            .into_iter()
            .map(|x| load_root_cert(&x))
            .collect::<Result<Vec<Certificate>, _>>()?;

        let verifier = Arc::new(RotCertVerifier::new(roots, log.clone())?)
            as Arc<dyn ClientCertVerifier>;

        let server_resolver =
            Arc::new(CertResolver::new(log.clone(), ResolveSetting::Ipcc))
                as Arc<dyn ResolvesServerCert>;

        let config =
            ServerConfig::builder_with_provider(Arc::new(crypto_provider()))
                .with_protocol_versions(&[&TLS13])?
                .with_client_cert_verifier(verifier)
                .with_cert_resolver(server_resolver);

        Ok(config)
    }

    pub async fn new(
        config: SprocketsConfig,
        addr: SocketAddrV6,
        log: slog::Logger,
    ) -> Result<Server, Error> {
        let c = match config.resolve {
            ResolveSetting::Local {
                priv_key,
                cert_chain,
            } => Server::new_tls_local_server_config(
                priv_key,
                cert_chain,
                config.roots,
                log.clone(),
            )?,
            ResolveSetting::Ipcc => {
                Server::new_tls_ipcc_server_config(config.roots, log.clone())?
            }
        };
        Server::listen(c, addr, log).await
    }

    async fn listen(
        tls_config: ServerConfig,
        listen_addr: SocketAddrV6,
        log: slog::Logger,
    ) -> Result<Server, Error> {
        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let tcp_listener = TcpListener::bind(&listen_addr).await?;
        Ok(Server {
            _log: log,
            tcp_listener,
            tls_acceptor,
        })
    }

    pub async fn accept(
        &mut self,
    ) -> Result<(Stream<TcpStream>, core::net::SocketAddr), Error> {
        let (stream, addr) = self.tcp_listener.accept().await?;
        let stream = self.tls_acceptor.clone().accept(stream).await?;

        Ok((Stream::new(stream.into()), addr))
    }

    pub async fn accept_measured(
        &mut self,
        corpus: &Vec<Utf8PathBuf>,
    ) -> Result<(Stream<TcpStream>, core::net::SocketAddr), Error> {
        let (stream, addr) = self.tcp_listener.accept().await?;

        let stream = self.tls_acceptor.clone().accept(stream).await?;

        let (_, state) = stream.get_ref();

        use crate::measurements::FromPkiPath;
        use der::Decode;
        if let Some(certs) = state.peer_certificates() {
            let mut chain = x509_cert::PkiPath::new();

            for c in certs {
                chain.push(Certificate::from_der(c.as_ref()).unwrap());
            }
            let platform_id =
                crate::measurements::PlatformId::from_pki_path(&chain).unwrap();
            println!(
                "Connection from peer {}",
                platform_id.unwrap().as_str().unwrap()
            );
        }
        crate::measurements::measure_from_corpus(corpus)?;

        Ok((Stream::new(stream.into()), addr))
    }
}
