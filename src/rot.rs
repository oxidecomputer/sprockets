
use msgs::*;

//! Implementation of the RoT sprocket

/// A key management and measurement service run on the RoT
pub struct RotSprocket {
    /// The key of the intermediate manufacturing cert that serves as the root
    /// of trust of this platform.
    manufacturing_public_key: Ed25519PublicKey,

    device_secret_key: Ed25519SecretKey,
    measurements_secret_key: Ed25519SecretKey,
    dhe_secret_key: Ed25519SecretKey,
   
    endorsements: Ed25519EndorsementsV1,

    /// Measurements get filled in by the running service
    rot_measurements: Option<RotMeasurementsV1>,
    sp_measurements: Option<SpMeasurementsV1>,
    hbs_measurements: Option<HbsMeasurementsV1>,
    host_measurements: Option<HostMeasurementsV1>,

    /// The expected value of measurements (shipped with fw update)
    corpus: CorpusV1,
}
