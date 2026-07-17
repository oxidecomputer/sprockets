// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The post-handshake sprockets attestation protocol.
//!
//! Once a mutually-authenticated TLS session exists, both peers run a
//! lock-step, client-first exchange over it: version negotiation, fresh
//! challenge nonces, attestation cert chains, measurement logs, and quotes,
//! followed by an appraisal of the peer's measurements against a reference
//! corpus. The two halves are [`client_exchange`] and [`server_exchange`].
//!
//! Everything here is transport-generic. The exchange functions are generic
//! over any `AsyncRead + AsyncWrite` stream and use only length-prefixed
//! [`send_msg`]/[`recv_msg`] framing over a single reliable ordered
//! bidirectional byte stream, so the same protocol bytes run unchanged over a
//! TCP-backed [`TlsStream`](tokio_rustls::TlsStream) or a QUIC bidirectional
//! stream. The one input the exchange cannot derive for itself is the peer's
//! trust-quorum [`PlatformId`], which comes from the handshake certificates;
//! the caller extracts it (see
//! [`platform_id_from_tls_certs`](crate::platform_id_from_tls_certs)) and hands
//! it in so the exchange can enforce the identity binding.

use crate::keys::{get_attest_data, AttestConfig, MeasurementConnectionPolicy};
use crate::Error;
use camino::Utf8PathBuf;
use dice_mfg_msgs::PlatformId;
use dice_verifier::{
    Attestation, Corim, Log, MeasurementSet, Nonce, Nonce32,
    ReferenceMeasurements,
};
use hubpack::SerializedSize;
use slog::{info, warn};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x509_cert::der::{Encode, Reader, SliceReader};
use x509_cert::Certificate;

// Response from the server, either the same version back, version - 1
// or an error if there is no way the server can support this request
type ProtocolResult = Result<u32, ()>;

// Message from client acking the version or telling the server it's
// giving up
type ProtocolRequestAck = Result<u32, ()>;

const CURRENT_PROTOCOL_VERSION: u32 = 2;
const PREVIOUS_PROTOCOL_VERSION: u32 = CURRENT_PROTOCOL_VERSION - 1;

/// The largest message [`recv_msg`] will accept.
///
/// The length prefix is peer-controlled and [`recv_msg`] allocates the full
/// message buffer before reading the body, so without a bound a
/// TLS-authenticated (but not yet attested) peer can demand a 4 GiB
/// allocation with a 4-byte prefix. 1 MiB comfortably exceeds every
/// legitimate protocol message: the largest are the hubpacked measurement
/// log and attestation, whose bounds are asserted below; cert chains and
/// nonces are far smaller.
const MAX_MSG_SIZE: usize = 1024 * 1024;

// The bound must admit every legitimate protocol message.
const _: () = assert!(dice_verifier::Log::MAX_SIZE <= MAX_MSG_SIZE);
const _: () = assert!(dice_verifier::Attestation::MAX_SIZE <= MAX_MSG_SIZE);

async fn recv_msg<T: AsyncReadExt + Unpin>(
    stream: &mut T,
) -> Result<Vec<u8>, Error> {
    // to receive a message we first get its length that is a u32 serialized as
    // a little endian byte array
    let mut msg_len = [0u8; 4];
    stream.read_exact(&mut msg_len).await?;
    let msg_len: usize = u32::from_le_bytes(msg_len).try_into()?;

    // The length is peer-controlled: bound it before allocating.
    if msg_len > MAX_MSG_SIZE {
        return Err(Error::MessageTooLarge {
            len: msg_len,
            max: MAX_MSG_SIZE,
        });
    }

    // with the length we can then get the message body
    let mut buf = vec![0u8; msg_len];
    stream.read_exact(&mut buf).await?;

    Ok(buf)
}

async fn send_msg<T: AsyncWriteExt + Unpin>(
    stream: &mut T,
    msg: &[u8],
) -> Result<(), Error> {
    // to send a message we first send the receiver its length as a u32
    // serialized as a little endian byte array
    let len: u32 = msg.len().try_into()?;
    stream.write_all(&len.to_le_bytes()).await?;
    // then we send the message
    Ok(stream.write_all(msg).await?)
}

fn certs_to_der(certs: &[Certificate]) -> Result<Vec<u8>, Error> {
    let mut der = Vec::new();

    for cert in certs {
        der.append(&mut cert.to_der()?);
    }

    Ok(der)
}

fn certs_from_der(buf: &[u8]) -> Result<Vec<Certificate>, Error> {
    let mut certs = Vec::new();
    let mut reader = SliceReader::new(buf)?;

    while !reader.is_finished() {
        certs.push(reader.decode()?);
    }

    Ok(certs)
}

/// Loads and CBOR-decodes the CoRIM reference-measurement corpus at `paths`.
///
/// The server loads its corpus *before* accepting the TLS connection, so a
/// malformed corpus aborts the handshake early rather than after attestation
/// work has begun; [`server_exchange`] then takes the loaded corpus by value.
/// [`client_exchange`], by contrast, loads its own corpus inline near the end
/// of the exchange — this asymmetry is wire-visible and deliberate.
pub(crate) fn corims_from_paths(
    paths: &[Utf8PathBuf],
    log: &slog::Logger,
) -> Result<Vec<Corim>, Error> {
    let mut corims = Vec::new();
    for c in paths {
        info!(log, "Using file {:?}", c);
        corims.push(Corim::from_file(c)?);
    }
    Ok(corims)
}

/// Runs the client half of the attestation exchange over an established TLS
/// session.
///
/// `stream` is the mutually-authenticated session; `tq_platform_id` is the
/// peer identity derived from its trust-quorum handshake certificates, against
/// which the peer's attestation cert chain must agree. On success returns the
/// peer's [`PlatformId`] and whether its measurements appraised successfully
/// against `corpus` (always `true` under
/// [`Enforced`](MeasurementConnectionPolicy::Enforced), since a failed
/// appraisal is an error there).
pub(crate) async fn client_exchange<T>(
    stream: &mut T,
    tq_platform_id: PlatformId,
    attest_config: &AttestConfig,
    roots: &[Certificate],
    corpus: Vec<Utf8PathBuf>,
    enforce: MeasurementConnectionPolicy,
    log: &slog::Logger,
) -> Result<(PlatformId, bool), Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // send version to the server
    send_msg(stream, &CURRENT_PROTOCOL_VERSION.to_le_bytes()).await?;

    // get version response from server, we expect it to be
    // hubpacked
    let version_response = recv_msg(stream).await?;
    let (version, _): (ProtocolResult, _) =
        hubpack::deserialize(&version_response)?;

    let version = match version {
        Ok(v) => v,
        // Not much we can do?
        Err(_) => return Err(Error::ProtocolVersion),
    };

    if version == CURRENT_PROTOCOL_VERSION {
        // we're good to go
        let mut buf = vec![0u8; ProtocolRequestAck::MAX_SIZE];
        let resp: ProtocolRequestAck = Ok(version);
        let resp_len = hubpack::serialize(&mut buf, &resp)?;
        send_msg(stream, &buf[..resp_len]).await?;
    } else if version == PREVIOUS_PROTOCOL_VERSION {
        // Also good
        let mut buf = vec![0u8; ProtocolRequestAck::MAX_SIZE];
        let resp: ProtocolRequestAck = Ok(version);
        let resp_len = hubpack::serialize(&mut buf, &resp)?;
        send_msg(stream, &buf[..resp_len]).await?;
    } else {
        // Farewell
        let mut buf = vec![0u8; ProtocolRequestAck::MAX_SIZE];
        let resp: ProtocolRequestAck = Err(());
        let resp_len = hubpack::serialize(&mut buf, &resp)?;
        send_msg(stream, &buf[..resp_len]).await?;
        return Err(Error::ProtocolVersion);
    }

    // Right now all protocols are the same
    info!(log, "Running with protocol version {version}");

    // send Nonce to server
    let nonce = Nonce::from_platform_rng(Nonce32::LENGTH)?;
    send_msg(stream, nonce.as_ref()).await?;

    // get Nonce from server
    let server_nonce = recv_msg(stream).await?;
    let server_nonce = Nonce::try_from(server_nonce)?;

    // get attestation & verify it before sending it
    // The attesation protocol has an inherent race condition between
    // getting the log and the attestation. We verify our own attestation
    // before sending it to the challenger to fail as early as possible.
    let attest_data = get_attest_data(attest_config, &server_nonce).await?;
    dice_verifier::verify_attestation(
        &attest_data.certs[0],
        &attest_data.attestation,
        &attest_data.log,
        &server_nonce,
    )?;

    // send client attestation cert chain to server
    let cert_chain_der = certs_to_der(&attest_data.certs)?;
    send_msg(stream, &cert_chain_der).await?;

    // get & verify server attestation cert chain
    let server_cert_chain = recv_msg(stream).await?;
    let server_cert_chain = certs_from_der(&server_cert_chain)?;
    let root =
        dice_verifier::verify_cert_chain(&server_cert_chain, Some(roots))?;
    let server_platform_id =
        dice_mfg_msgs::PlatformId::try_from(&server_cert_chain)?;
    info!(
        log,
        "Cert chain from peer \"{}\" verified against root \"{}\"",
        server_platform_id.as_str(),
        root.tbs_certificate.subject,
    );

    if tq_platform_id != server_platform_id {
        return Err(Error::PlatformIdMismatch);
    }
    info!(log, "TQ & attestation cert chains agree on platform id");

    // send measurement log to server
    let mut buf = vec![0u8; Log::MAX_SIZE];
    let log_len = hubpack::serialize(&mut buf, &attest_data.log)?;
    send_msg(stream, &buf[..log_len]).await?;

    // get measurement log from server
    let server_log = recv_msg(stream).await?;
    let (server_log, _): (Log, _) = hubpack::deserialize(&server_log)?;

    // hubpack attestation and send to server
    let mut buf = vec![0u8; Attestation::MAX_SIZE];
    let len = hubpack::serialize(&mut buf, &attest_data.attestation)?;
    send_msg(stream, &buf[..len]).await?;

    // get attestation from server
    let server_attestation = recv_msg(stream).await?;
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

    // load corims into a set of ReferenceMeasurements
    let mut corims = Vec::new();
    for c in corpus {
        corims.push(Corim::from_file(c)?);
    }

    for c in attest_data.test_corpus {
        corims.push(Corim::from_file(c)?);
    }
    let reference_measurements =
        ReferenceMeasurements::try_from(corims.as_slice())?;

    // appraise measurements from server attestation against reference
    // measurements
    let measurements =
        MeasurementSet::from_artifacts(&server_cert_chain, &server_log)?;
    let result = match dice_verifier::verify_measurements(
        &measurements,
        &reference_measurements,
    ) {
        Ok(()) => {
            info!(log, "Peer measurements appraised successfully");
            true
        }
        Err(err) => {
            warn!(
                log,
                "Peer ({}) measurements appraisal failed {} corpus {}",
                server_platform_id.as_str(),
                err,
                reference_measurements
            );
            match enforce {
                MeasurementConnectionPolicy::Enforced => {
                    return Err(Error::AttestMeasurementsVerifier {
                        peer: server_platform_id,
                        err,
                    });
                }
                MeasurementConnectionPolicy::Permissive => false,
            }
        }
    };
    Ok((server_platform_id, result))
}

/// Runs the server half of the attestation exchange over an established TLS
/// session.
///
/// `stream` is the mutually-authenticated session; `tq_platform_id` is the peer
/// identity derived from its trust-quorum handshake certificates; `corims` is
/// the reference-measurement corpus loaded before the handshake (see
/// [`corims_from_paths`]). On success returns the peer's [`PlatformId`] and
/// whether its measurements appraised successfully (always `true` under
/// [`Enforced`](MeasurementConnectionPolicy::Enforced)).
///
/// The server's wire behavior is deliberately asymmetric to the client's: it
/// sends its own attestation *last*, only after appraising the client, and
/// under [`Enforced`](MeasurementConnectionPolicy::Enforced) a failed appraisal
/// returns before that final send ever happens.
pub(crate) async fn server_exchange<T>(
    stream: &mut T,
    tq_platform_id: PlatformId,
    mut corims: Vec<Corim>,
    attest_config: &AttestConfig,
    roots: &[Certificate],
    enforce: MeasurementConnectionPolicy,
    log: &slog::Logger,
) -> Result<(PlatformId, bool), Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // get version from the client
    let version_bytes = recv_msg(stream).await?;
    // Anything but exactly the 4-byte little-endian version is protocol
    // garbage from the peer; reject it rather than index past the end of a
    // short message.
    let version_bytes: [u8; 4] = version_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::ProtocolVersion)?;
    let version = u32::from_le_bytes(version_bytes);

    if version == CURRENT_PROTOCOL_VERSION {
        // we're good to go
        let mut buf = vec![0u8; ProtocolResult::MAX_SIZE];
        let resp: ProtocolResult = Ok(version);
        let resp_len = hubpack::serialize(&mut buf, &resp)?;
        send_msg(stream, &buf[..resp_len]).await?;
    } else if version == PREVIOUS_PROTOCOL_VERSION {
        // We eventually want to support older protocol
        let mut buf = vec![0u8; ProtocolResult::MAX_SIZE];
        let resp: ProtocolResult = Ok(version);
        let resp_len = hubpack::serialize(&mut buf, &resp)?;
        send_msg(stream, &buf[..resp_len]).await?;
    } else {
        // We can't deal with this
        // We eventually want to support older protocol
        let mut buf = vec![0u8; ProtocolResult::MAX_SIZE];
        let resp: ProtocolResult = Err(());
        let resp_len = hubpack::serialize(&mut buf, &resp)?;
        send_msg(stream, &buf[..resp_len]).await?;
        // Client has given us something bad, time to give up
        return Err(Error::ProtocolVersion);
    }

    // Wait for the protocol ACK
    let protocol_ack_bytes = recv_msg(stream).await?;
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
    let client_nonce = recv_msg(stream).await?;
    let client_nonce = Nonce::try_from(client_nonce)?;

    // generate & send Nonce to client
    let nonce = Nonce::from_platform_rng(Nonce32::LENGTH)?;
    send_msg(stream, nonce.as_ref()).await?;

    // get attestation & verify it before sending it
    // The attesation protocol has an inherent race condition between
    // getting the log and the attestation. We verify our own attestation
    // before sending it to the challenger to fail as early as possible.
    let attest_data = get_attest_data(attest_config, &client_nonce).await?;
    dice_verifier::verify_attestation(
        &attest_data.certs[0],
        &attest_data.attestation,
        &attest_data.log,
        &client_nonce,
    )?;

    // get & verify client attestation cert chain
    let client_cert_chain = recv_msg(stream).await?;
    let client_cert_chain = certs_from_der(&client_cert_chain)?;
    let root =
        dice_verifier::verify_cert_chain(&client_cert_chain, Some(roots))?;
    let client_platform_id =
        dice_mfg_msgs::PlatformId::try_from(&client_cert_chain)?;
    info!(
        log,
        "Cert chain from peer \"{}\" verified against root \"{}\"",
        client_platform_id.as_str(),
        root.tbs_certificate.subject,
    );

    if tq_platform_id != client_platform_id {
        return Err(Error::PlatformIdMismatch);
    }
    info!(log, "TQ & attestation cert chains agree on platform id");

    // send server attestation cert chain to client
    let cert_chain_der = certs_to_der(&attest_data.certs)?;
    send_msg(stream, &cert_chain_der).await?;

    // get measurement log from client
    let client_log = recv_msg(stream).await?;
    let (client_log, _): (Log, _) = hubpack::deserialize(&client_log)?;

    // send server measurement log to client
    let mut buf = vec![0u8; Log::MAX_SIZE];
    let len = hubpack::serialize(&mut buf, &attest_data.log)?;
    send_msg(stream, &buf[..len]).await?;

    // get attestation from client
    let client_attestation = recv_msg(stream).await?;
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

    for c in attest_data.test_corpus {
        corims.push(Corim::from_file(c)?);
    }

    let corpus = ReferenceMeasurements::try_from(corims.as_slice())?;
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
            Err(err) => {
                warn!(
                    log,
                    "Peer ({}) measurements appraisal failed: {} corpus {}",
                    client_platform_id.as_str(),
                    err,
                    corpus
                );
                match enforce {
                    MeasurementConnectionPolicy::Enforced => {
                        return Err(Error::AttestMeasurementsVerifier {
                            peer: client_platform_id,
                            err,
                        });
                    }
                    MeasurementConnectionPolicy::Permissive => false,
                }
            }
        };

    // hubpack the attestation and send to client
    let mut buf = vec![0u8; Attestation::MAX_SIZE];
    let len = hubpack::serialize(&mut buf, &attest_data.attestation)?;
    send_msg(stream, &buf[..len]).await?;

    Ok((client_platform_id, result))
}
