// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A TLS based client

use rustls::pki_types::ServerName;
use std::net::SocketAddrV6;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::keys::{get_attest_data, AttestConfig, ResolveSetting};
use crate::keys::{CertResolver, RotCertVerifier, SprocketsConfig};
use crate::{
    certs_from_der, certs_to_der, crypto_provider, load_root_cert, recv_msg,
    send_msg,
};
use crate::{Error, Stream};
use camino::Utf8PathBuf;
use dice_mfg_msgs::PlatformId;
use dice_verifier::{
    Attestation, Corim, Log, MeasurementSet, Nonce, ReferenceMeasurements,
};
use hubpack::SerializedSize;
use rustls::{
    client::{
        danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        },
        ResolvesClientCert,
    },
    sign::CertifiedKey,
    version::TLS13,
    ClientConfig, SignatureScheme,
};
use slog::{error, info};
use x509_cert::{der::Decode, Certificate};

impl ResolvesClientCert for CertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        // TODO: Do we need to use `_root_hint_subjects`?

        // We only support Ed25519
        if !sigschemes.iter().all(|&s| s == SignatureScheme::ED25519) {
            error!(
                self.log,
                "Invalid signature schemes requested: {:?}", sigschemes
            );
            return None;
        }
        match self.load_certified_key() {
            Ok(key) => {
                info!(self.log, "Loaded keys and certs");
                Some(key)
            }
            Err(e) => {
                error!(self.log, "failed to load certified key: {e}");
                None
            }
        }
    }

    fn has_certs(&self) -> bool {
        true
    }
}

impl ServerCertVerifier for RotCertVerifier {
    // We explicitly ignore the timestamp since we may be operating before the
    // rack has proper time.
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // TODO: Validate `server_name` and `ocsp_response`?
        self.verify_cert(end_entity, intermediates)?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
    {
        // We don't allow the use of TLS 1.2
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_signature(message, cert, dss.signature())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// The top-level sprockets client
pub struct Client {}

impl Client {
    /// Connect to a listening server at the provided `addr`ess according to
    /// the `config`uration provided. Before the stream is returned to the
    /// client
    /// - the TLS handshake will be completed and mutually authenticated
    ///   against the roots from the `config`
    /// - the attestation process is carried out with peer credentials
    ///   authenticated by the roots from the `config` and peer measurements
    ///   appraised using the provided `corpus`
    ///
    /// NOTE: This function is not cancel safe and should be run in a dedicated
    /// task.
    pub async fn connect(
        config: SprocketsConfig,
        addr: SocketAddrV6,
        corpus: Vec<Utf8PathBuf>,
        log: slog::Logger,
    ) -> Result<(Stream<TcpStream>, PlatformId), Error> {
        use x509_cert::der::DecodePem;

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
            } => Client::new_tls_local_client_config(
                priv_key,
                cert_chain,
                config.roots,
                log.clone(),
            )?,
            ResolveSetting::Ipcc => {
                Client::new_tls_ipcc_client_config(config.roots, log.clone())?
            }
        };

        // load corims into a set of ReferenceMeasurements
        let mut corims = Vec::new();
        for c in corpus {
            corims.push(Corim::from_file(c)?);
        }
        let corpus = ReferenceMeasurements::try_from(corims.as_slice())?;

        Client::connect_with_config(c, config.attest, roots, corpus, addr, log)
            .await
    }

    fn new_tls_local_client_config(
        priv_key: Utf8PathBuf,
        cert_chain: Utf8PathBuf,
        roots: Vec<Utf8PathBuf>,
        log: slog::Logger,
    ) -> Result<ClientConfig, Error> {
        let roots = roots
            .into_iter()
            .map(|x| load_root_cert(&x))
            .collect::<Result<Vec<Certificate>, _>>()?;

        let verifier = Arc::new(RotCertVerifier::new(roots, log.clone())?)
            as Arc<dyn ServerCertVerifier>;

        let client_resolver = Arc::new(CertResolver::new(
            log.clone(),
            ResolveSetting::Local {
                priv_key,
                cert_chain,
            },
        )) as Arc<dyn ResolvesClientCert>;

        let config =
            ClientConfig::builder_with_provider(Arc::new(crypto_provider()))
                .with_protocol_versions(&[&TLS13])?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_client_cert_resolver(client_resolver);

        Ok(config)
    }

    fn new_tls_ipcc_client_config(
        roots: Vec<Utf8PathBuf>,
        log: slog::Logger,
    ) -> Result<ClientConfig, Error> {
        let roots = roots
            .into_iter()
            .map(|x| load_root_cert(&x))
            .collect::<Result<Vec<Certificate>, _>>()?;

        let verifier = Arc::new(RotCertVerifier::new(roots, log.clone())?)
            as Arc<dyn ServerCertVerifier>;

        let client_resolver =
            Arc::new(CertResolver::new(log.clone(), ResolveSetting::Ipcc))
                as Arc<dyn ResolvesClientCert>;

        let config =
            ClientConfig::builder_with_provider(Arc::new(crypto_provider()))
                .with_protocol_versions(&[&TLS13])?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_client_cert_resolver(client_resolver);

        Ok(config)
    }

    /// Connect to a remote peer
    async fn connect_with_config(
        tls_config: ClientConfig,
        attest_config: AttestConfig,
        roots: Vec<Certificate>,
        reference_measurements: ReferenceMeasurements,
        addr: SocketAddrV6,
        log: slog::Logger,
    ) -> Result<(Stream<TcpStream>, PlatformId), Error> {
        // Nodes on the bootstrap network don't have DNS names. We don't
        // actually ever know who we are connecting to on the bootstrap
        // network, as we just learned of potential peers by IPv6 address from
        // DDMD. We learn the identities of peers from the subject name in the
        // certificate. Because of this we always pass a dummy DNS name, and
        // ignore it when validating the connection on the server side.
        let dnsname = ServerName::try_from("unknown.com").unwrap();

        let connector = TlsConnector::from(Arc::new(tls_config));
        let stream = match TcpStream::connect(addr).await {
            Ok(s) => s,
            Err(e) => {
                println!("{e:?}");
                return Err(e.into());
            }
        };

        let mut stream = connector.connect(dnsname, stream).await?;

        // get server cert chain from connection
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

        // send Nonce to server
        let nonce = Nonce::from_platform_rng()?;
        send_msg(&mut stream, nonce.as_ref()).await?;

        // get Nonce from server
        let server_nonce = recv_msg(&mut stream).await?;
        let server_nonce = Nonce::try_from(server_nonce)?;

        // get attestation & verify it before sending it
        // The attesation protocol has an inherent race condition between
        // getting the log and the attestation. We verify our own attestation
        // before sending it to the challenger to fail as early as possible.
        let attest_data = get_attest_data(&attest_config, &server_nonce)?;
        dice_verifier::verify_attestation(
            &attest_data.certs[0],
            &attest_data.attestation,
            &attest_data.log,
            &server_nonce,
        )?;

        // send client attestation cert chain to server
        let cert_chain_der = certs_to_der(&attest_data.certs)?;
        send_msg(&mut stream, &cert_chain_der).await?;

        // get & verify server attestation cert chain
        let server_cert_chain = recv_msg(&mut stream).await?;
        let server_cert_chain = certs_from_der(&server_cert_chain)?;
        let root =
            dice_verifier::verify_cert_chain(&server_cert_chain, Some(&roots))?;
        let server_platform_id =
            dice_mfg_msgs::PlatformId::try_from(&server_cert_chain)?;
        info!(
            log,
            "Cert chain from peer \"{}\" verified against root \"{}\"",
            server_platform_id.as_str()?,
            root.tbs_certificate.subject,
        );

        if tq_platform_id != server_platform_id {
            return Err(Error::PlatformIdMismatch);
        }
        info!(log, "TQ & attestation cert chains agree on platform id");

        // send measurement log to server
        let mut buf = vec![0u8; Log::MAX_SIZE];
        let log_len = hubpack::serialize(&mut buf, &attest_data.log)?;
        send_msg(&mut stream, &buf[..log_len]).await?;

        // get measurement log from server
        let server_log = recv_msg(&mut stream).await?;
        let (server_log, _): (Log, _) = hubpack::deserialize(&server_log)?;

        // hubpack attestation and send to server
        let mut buf = vec![0u8; Attestation::MAX_SIZE];
        let len = hubpack::serialize(&mut buf, &attest_data.attestation)?;
        send_msg(&mut stream, &buf[..len]).await?;

        // get attestation from server
        let server_attestation = recv_msg(&mut stream).await?;
        let (server_attestation, _): (Attestation, _) =
            hubpack::deserialize(&server_attestation)?;

        // verify server attestation
        dice_verifier::verify_attestation(
            &server_cert_chain[0],
            &server_attestation,
            &server_log,
            &nonce,
        )?;
        info!(log, "Peer attestation verified");

        // appraise measurements from server attestation against reference
        // measurements
        let measurements =
            MeasurementSet::from_artifacts(&server_cert_chain, &server_log)?;
        dice_verifier::verify_measurements(
            &measurements,
            &reference_measurements,
        )?;
        info!(log, "Peer measurements appraised successfully");

        Ok((Stream::new(stream.into()), server_platform_id))
    }
}

#[cfg(test)]
mod tests {
    use crate::keys::CertResolver;
    use crate::keys::ResolveSetting;
    use crate::keys::RotCertVerifier;
    use crate::load_root_cert;
    use crate::tests::logger;
    use camino::Utf8PathBuf;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::ServerName;
    use rustls::SignatureScheme;

    #[test]
    // Ensure the test certs can be loaded and verified
    fn test_client_verifier() {
        let mut pki_keydir = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pki_keydir.push("test-keys");
        let root =
            load_root_cert(&pki_keydir.join("test-root-a.cert.pem")).unwrap();
        let verifier = RotCertVerifier::new(vec![root], logger()).unwrap();
        let resolver = CertResolver::new(
            logger(),
            ResolveSetting::Local {
                priv_key: pki_keydir.join("test-sprockets-auth-1.key.pem"),
                cert_chain: pki_keydir
                    .join("test-sprockets-auth-1.certlist.pem"),
            },
        );
        let certified_key = resolver.load_certified_key().unwrap();
        let end_entity = certified_key.end_entity_cert().unwrap();
        let intermediates = &certified_key.cert[1..];
        let server_name: ServerName = "example.com".try_into().unwrap();

        // Verify that the cert chain is valid
        verifier
            .verify_server_cert(
                end_entity,
                intermediates,
                &server_name,
                &[],
                rustls::pki_types::UnixTime::now(),
            )
            .unwrap();

        // Now create a signature over an arbitrary message using our
        // LocalEd25519Signer and then verify it.
        let message = b"sign-me-then-verify-me";
        let signer = certified_key
            .key
            .choose_scheme(&[SignatureScheme::ED25519])
            .unwrap();
        let signature = signer.sign(message).unwrap();
        let res = verifier.verify_signature(message, end_entity, &signature);
        assert!(res.is_ok());
    }
}
