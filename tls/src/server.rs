// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A TLS based server

use crate::keys::{
    get_attest_data, AttestConfig, CertResolver, ResolveSetting,
    RotCertVerifier, SprocketsConfig,
};
use crate::{
    certs_from_der, certs_to_der, crypto_provider, load_root_cert, recv_msg,
    send_msg, ProtocolRequestAck, ProtocolResult, CURRENT_PROTOCOL_VERSION,
    PREVIOUS_PROTOCOL_VERSION,
};
use crate::{Error, Stream};
use camino::Utf8PathBuf;
use dice_verifier::{
    Attestation, Corim, Log, MeasurementSet, Nonce, ReferenceMeasurements,
};
use hubpack::SerializedSize;
use rustls::{
    server::{
        danger::{ClientCertVerified, ClientCertVerifier},
        ResolvesServerCert,
    },
    version::TLS13,
    CipherSuite, ServerConfig, SignatureScheme,
};
use slog::{error, info};
use std::net::{SocketAddr, SocketAddrV6};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use x509_cert::{
    der::{Decode, DecodePem},
    Certificate,
};

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

pub struct SprocketsAcceptor {
    stream: TcpStream,
    addr: SocketAddr,
    log: slog::Logger,
    tls_acceptor: TlsAcceptor,
    attest_config: AttestConfig,
    roots: Vec<Certificate>,
    corpus: Vec<Utf8PathBuf>,
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
        } = self;

        // load corims into a set of ReferenceMeasurements
        let mut corims = Vec::new();
        for c in corpus {
            corims.push(Corim::from_file(c)?);
        }
        let corpus = ReferenceMeasurements::try_from(corims.as_slice())?;

        let mut stream = tls_acceptor.clone().accept(stream).await?;

        // get PlatformId from server TLS / Trust Quorum cert chain
        let (_, conn) = stream.get_ref();
        let tq_platform_id = if let Some(tls_certs) = conn.peer_certificates() {
            let mut pki_path = Vec::new();
            for der in tls_certs.iter() {
                pki_path.push(Certificate::from_der(der).map_err(|_| {
                    rustls::Error::InvalidCertificate(
                        rustls::CertificateError::BadEncoding,
                    )
                })?)
            }
            dice_mfg_msgs::PlatformId::try_from(&pki_path)?
        } else {
            return Err(Error::NoTQCerts);
        };

        // get version from the client
        let version_bytes = recv_msg(&mut stream).await?;
        let version =
            u32::from_le_bytes(version_bytes[..4].try_into().unwrap());

        if version == CURRENT_PROTOCOL_VERSION {
            // we're good to go
            let mut buf = vec![0u8; ProtocolResult::MAX_SIZE];
            let resp: ProtocolResult = Ok(version);
            let resp_len = hubpack::serialize(&mut buf, &resp)?;
            send_msg(&mut stream, &buf[..resp_len]).await?;
        } else if version == PREVIOUS_PROTOCOL_VERSION {
            // We eventually want to support older protocol
            let mut buf = vec![0u8; ProtocolResult::MAX_SIZE];
            let resp: ProtocolResult = Ok(version);
            let resp_len = hubpack::serialize(&mut buf, &resp)?;
            send_msg(&mut stream, &buf[..resp_len]).await?;
        } else {
            // We can't deal with this
            // We eventually want to support older protocol
            let mut buf = vec![0u8; ProtocolResult::MAX_SIZE];
            let resp: ProtocolResult = Err(());
            let resp_len = hubpack::serialize(&mut buf, &resp)?;
            send_msg(&mut stream, &buf[..resp_len]).await?;
            // Client has given us something bad, time to give up
            return Err(Error::ProtocolVersion);
        }

        // Wait for the protocol ACK
        let protocol_ack_bytes = recv_msg(&mut stream).await?;
        let (protocol_ack, _): (ProtocolRequestAck, _) =
            hubpack::deserialize(&protocol_ack_bytes)?;

        match protocol_ack {
            Ok(v) => {
                if v != version {
                    // this isn't right...
                    return Err(Error::ClientMismatch);
                }
            }
            Err(_) => return Err(Error::ClientGaveUp),
        }

        // Right now all protocols are the same
        info!(log, "Running with protocol version {version}");

        // get Nonce from client
        let client_nonce = recv_msg(&mut stream).await?;
        let client_nonce = Nonce::try_from(client_nonce)?;

        // generate & send Nonce to client
        let nonce = Nonce::from_platform_rng()?;
        send_msg(&mut stream, nonce.as_ref()).await?;

        // get attestation & verify it before sending it
        // The attesation protocol has an inherent race condition between
        // getting the log and the attestation. We verify our own attestation
        // before sending it to the challenger to fail as early as possible.
        let attest_data = get_attest_data(&attest_config, &client_nonce)?;
        dice_verifier::verify_attestation(
            &attest_data.certs[0],
            &attest_data.attestation,
            &attest_data.log,
            &client_nonce,
        )?;

        // get & verify client attestation cert chain
        let client_cert_chain = recv_msg(&mut stream).await?;
        let client_cert_chain = certs_from_der(&client_cert_chain)?;
        let root =
            dice_verifier::verify_cert_chain(&client_cert_chain, Some(&roots))?;
        let client_platform_id =
            dice_mfg_msgs::PlatformId::try_from(&client_cert_chain)?;
        info!(
            log,
            "Cert chain from peer \"{}\" verified against root \"{}\"",
            client_platform_id.as_str()?,
            root.tbs_certificate.subject,
        );

        if tq_platform_id != client_platform_id {
            return Err(Error::PlatformIdMismatch);
        }
        info!(log, "TQ & attestation cert chains agree on platform id");

        // send server attestation cert chain to client
        let cert_chain_der = certs_to_der(&attest_data.certs)?;
        send_msg(&mut stream, &cert_chain_der).await?;

        // get measurement log from client
        let client_log = recv_msg(&mut stream).await?;
        let (client_log, _): (Log, _) = hubpack::deserialize(&client_log)?;

        // send server measurement log to client
        let mut buf = vec![0u8; Log::MAX_SIZE];
        let len = hubpack::serialize(&mut buf, &attest_data.log)?;
        send_msg(&mut stream, &buf[..len]).await?;

        // get attestation from client
        let client_attestation = recv_msg(&mut stream).await?;
        let (client_attestation, _): (Attestation, _) =
            hubpack::deserialize(&client_attestation)?;

        // verify client attestation
        dice_verifier::verify_attestation(
            &client_cert_chain[0],
            &client_attestation,
            &client_log,
            &nonce,
        )?;
        info!(log, "Peer attestation verified");

        // appraise measurements from client attestation against reference
        // measurements
        let measurements =
            MeasurementSet::from_artifacts(&client_cert_chain, &client_log)?;
        let result =
            match dice_verifier::verify_measurements(&measurements, &corpus) {
                Ok(()) => {
                    info!(log, "Peer measurements appraised successfully");
                    true
                }
                Err(e) => {
                    info!(log, "Peer measurements appraisal failed: {}", e);
                    false
                }
            };

        // hubpack the attestation and send to client
        let mut buf = vec![0u8; Attestation::MAX_SIZE];
        let len = hubpack::serialize(&mut buf, &attest_data.attestation)?;
        send_msg(&mut stream, &buf[..len]).await?;

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
        let mut roots = Vec::new();
        for root in &config.roots {
            let root = std::fs::read(root)?;
            let root = Certificate::from_pem(&root)?;
            roots.push(root);
        }

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
        Server::listen(c, config.attest, roots, addr, log).await
    }

    async fn listen(
        tls_config: ServerConfig,
        attest_config: AttestConfig,
        roots: Vec<Certificate>,
        listen_addr: SocketAddrV6,
        log: slog::Logger,
    ) -> Result<Server, Error> {
        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let tcp_listener = TcpListener::bind(&listen_addr).await?;
        Ok(Server {
            attest_config,
            log,
            tcp_listener,
            tls_acceptor,
            roots,
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
        })
    }
}
