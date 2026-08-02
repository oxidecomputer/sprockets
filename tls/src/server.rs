// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A TLS based server

use crate::attest;
use crate::config::{load_roots, new_tls_server_config};
use crate::keys::{
    AttestConfig, CertResolver, MeasurementConnectionPolicy, RotCertVerifier,
    SprocketsConfig,
};
use crate::{platform_id_from_tls_certs, Error, Stream};
use camino::Utf8PathBuf;
use rustls::{
    server::{
        danger::{ClientCertVerified, ClientCertVerifier},
        ResolvesServerCert,
    },
    CipherSuite, ServerConfig, SignatureScheme,
};
use slog::error;
use std::net::{SocketAddr, SocketAddrV6};
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
                error!(self.log, "failed to load certified key"; e);
                None
            }
        }
    }
}

pub struct SprocketsAcceptor {
    stream: TcpStream,
    addr: SocketAddr,
    log: slog::Logger,
    tls_acceptor: TlsAcceptor,
    attest_config: AttestConfig,
    roots: Vec<Certificate>,
    corpus: Vec<Utf8PathBuf>,
    enforce: MeasurementConnectionPolicy,
}

impl SprocketsAcceptor {
    pub async fn handshake(
        self,
    ) -> Result<(Stream<TcpStream>, SocketAddr), Error> {
        let SprocketsAcceptor {
            stream,
            addr,
            log,
            tls_acceptor,
            attest_config,
            roots,
            corpus,
            enforce,
        } = self;

        // Load the reference-measurement corpus before accepting the
        // connection, so a malformed corpus aborts the handshake early.
        let corims = attest::corims_from_paths(&corpus, &log)?;

        let mut stream = tls_acceptor.clone().accept(stream).await?;

        // get PlatformId from server TLS / Trust Quorum cert chain
        let (_, conn) = stream.get_ref();
        let tq_platform_id =
            platform_id_from_tls_certs(conn.peer_certificates())?;

        let (client_platform_id, result) = attest::server_exchange(
            &mut stream,
            tq_platform_id,
            corims,
            &attest_config,
            &roots,
            enforce,
            &log,
        )
        .await?;

        Ok((Stream::new(stream.into(), client_platform_id, result), addr))
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
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
    log: slog::Logger,
    tcp_listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    roots: Vec<Certificate>,
    attest_config: AttestConfig,
    enforce: MeasurementConnectionPolicy,
}

impl Server {
    // Return the actual address and port being listened on.
    //
    // Sometimes the actual listen port changes because the given port is 0. Using 0
    // is useful for testing, but we need some way to get the real port out.
    pub fn listen_addr(&self) -> std::io::Result<SocketAddr> {
        self.tcp_listener.local_addr()
    }

    pub async fn new(
        config: SprocketsConfig,
        addr: SocketAddrV6,
        log: slog::Logger,
    ) -> Result<Server, Error> {
        let roots = load_roots(&config.roots)?;
        let tls_config =
            new_tls_server_config(config.resolve, roots.clone(), &log)?;

        Server::listen(
            tls_config,
            config.attest,
            roots,
            addr,
            log,
            config.enforce,
        )
        .await
    }

    async fn listen(
        tls_config: ServerConfig,
        attest_config: AttestConfig,
        roots: Vec<Certificate>,
        listen_addr: SocketAddrV6,
        log: slog::Logger,
        enforce: MeasurementConnectionPolicy,
    ) -> Result<Server, Error> {
        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let tcp_listener = TcpListener::bind(&listen_addr).await?;
        Ok(Server {
            attest_config,
            log,
            tcp_listener,
            tls_acceptor,
            roots,
            enforce,
        })
    }

    pub async fn accept(
        &self,
        corpus: Vec<Utf8PathBuf>,
    ) -> Result<SprocketsAcceptor, Error> {
        let (stream, addr) = self.tcp_listener.accept().await?;

        Ok(SprocketsAcceptor {
            stream,
            addr,
            log: self.log.clone(),
            tls_acceptor: self.tls_acceptor.clone(),
            attest_config: self.attest_config.clone(),
            roots: self.roots.clone(),
            corpus,
            enforce: self.enforce,
        })
    }
}
