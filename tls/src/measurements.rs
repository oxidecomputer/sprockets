// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::Error;
use attest_data::{Log, Measurement, Sha3_256Digest};
use camino::Utf8PathBuf;
use const_oid::db::rfc4519::{COMMON_NAME, COUNTRY_NAME, ORGANIZATION_NAME};
use const_oid::{AssociatedOid, ObjectIdentifier};
use der::{
    asn1::OctetString, Decode, DecodeValue, Header, Sequence, SliceReader,
};
use rats_corim::Corim;
use std::collections::HashSet;

pub use dice_mfg_msgs::PlatformId;
use sha3::Sha3_256;
use x509_cert::{
    der::{
        asn1::{PrintableString, Utf8StringRef},
        Tag, Tagged,
    },
    PkiPath,
};

pub fn corim_to_set(
    paths: &Vec<Utf8PathBuf>,
) -> Result<HashSet<Measurement>, Error> {
    let mut set = HashSet::new();
    for path in paths {
        let corim = Corim::from_file(path.into()).map_err(Error::Corim)?;
        for m in corim.iter_measurements() {
            set.insert(Measurement::Sha3_256(m.try_into().unwrap()));
        }
    }
    Ok(set)
}

// Replace with something in `attest_data`,

// DICE Attestation Architecture §6.1.1:
// FWID ::== SEQUENCE {
#[derive(Debug, Sequence)]
pub struct Fwid {
    // hashAlg OBJECT IDENTIFIER,
    hash_algorithm: ObjectIdentifier,
    // digest OCTET STRING
    digest: OctetString,
}

// DICE Attestation Architecture §6.1.1:
// DiceTcbInfo ::== SEQUENCE {
#[derive(Debug, Sequence)]
pub struct DiceTcbInfo {
    // fwids [6] IMPLICIT FWIDLIST OPTIONAL,
    // where FWIDLIST ::== SEQUENCE SIZE (1..MAX) OF FWID
    #[asn1(context_specific = "6", tag_mode = "IMPLICIT", optional = "true")]
    fwids: Option<Vec<Fwid>>,
}

trait FromFwid {
    fn from_fwid(fwid: &Fwid) -> Result<Self, Error>
    where
        Self: Sized;
}

impl FromFwid for Measurement {
    fn from_fwid(fwid: &Fwid) -> Result<Self, Error> {
        // map from fwid.hash_algorithm ObjectIdentifier to Measurement enum
        if fwid.hash_algorithm == Sha3_256::OID {
            // pull the associated data from fwid.digest OctetString
            let digest = fwid.digest.as_bytes();
            let digest = Sha3_256Digest::try_from(digest).unwrap();

            Ok(Measurement::Sha3_256(digest))
        } else {
            //Err(anyhow!("Unsupported Measurement digest: Sha3_256"))
            panic!("bad digest");
        }
    }
}

// this doesn't belong here ... maybe `attest-data`?
const DICE_TCB_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.23.133.5.4.1");

pub fn artifacts_to_set(
    pki_path: &PkiPath,
    log: &Log,
) -> Result<HashSet<Measurement>, Error> {
    let mut measurements = HashSet::new();

    for cert in pki_path {
        if let Some(extensions) = &cert.tbs_certificate.extensions {
            for ext in extensions {
                if ext.extn_id == DICE_TCB_INFO {
                    //if !ext.critical {
                    //    warn!("DiceTcbInfo extension is non-critical");
                    //}

                    let mut reader =
                        SliceReader::new(ext.extn_value.as_bytes())?;
                    let header = Header::decode(&mut reader).unwrap();

                    let tcb_info =
                        DiceTcbInfo::decode_value(&mut reader, header).unwrap();
                    if let Some(fwid_vec) = &tcb_info.fwids {
                        for fwid in fwid_vec {
                            let measurement =
                                Measurement::from_fwid(fwid).unwrap();
                            measurements.insert(measurement);
                        }
                    }
                }
            }
        }
    }

    for measurement in log.iter() {
        measurements.insert(*measurement);
    }

    Ok(measurements)
}

pub enum MeasureResult {
    Ok,
    NotASubset,
    EmptyCorpus,
}

pub fn measure_from_corpus(
    corpus: &Vec<Utf8PathBuf>,
) -> Result<MeasureResult, Error> {
    if corpus.is_empty() {
        return Ok(MeasureResult::EmptyCorpus);
    }

    let corpus = crate::measurements::corim_to_set(corpus)?;

    let ipcc = crate::ipcc::Ipcc::new().map_err(crate::Error::RotRequest)?;
    let log = ipcc.get_measurement_log()?;
    let certs = ipcc.get_certificates()?;

    let measurements = crate::measurements::artifacts_to_set(&certs, &log)?;

    if !measurements.is_subset(&corpus) {
        return Ok(MeasureResult::NotASubset);
    }

    Ok(MeasureResult::Ok)
}

pub trait FromPkiPath {
    fn from_pki_path(pki_path: &PkiPath) -> Result<Option<Self>, Error>
    where
        Self: Sized;
}

impl FromPkiPath for PlatformId {
    // Find the PlatformId in the provided cert chain. This value is stored in
    // cert's `Subject` field. The Subject field C / Country and O /
    // Organization must always be'US' and 'Oxide Computer Company'
    // respectively. The PlatformId string is stored in the Subject CN /
    // commonName. We validate its format using the dice_mfg_msgs::PlatformId
    // type. If one PlatformId is found it is returned. If none are found then
    // None is returned. The path must have only one cert w/ a valid
    // PlatformId, if more than one is found an error is returned.
    fn from_pki_path(pki_path: &PkiPath) -> Result<Option<Self>, Error> {
        let mut platform_id: Option<PlatformId> = None;
        for cert in pki_path {
            for elm in &cert.tbs_certificate.subject.0 {
                for atav in elm.0.iter() {
                    if atav.oid == COUNTRY_NAME {
                        if atav.value.tag() != Tag::PrintableString {
                            panic!("Invalid tag for Subject countryName");
                        }
                        let country =
                            PrintableString::try_from(&atav.value).unwrap();
                        let country: &str = country.as_ref();
                        if country != "US" {
                            panic!("Invalid countryName");
                        }
                    } else if atav.oid == ORGANIZATION_NAME {
                        if atav.value.tag() != Tag::Utf8String {
                            panic!("Invalid tag for Subject organizationName");
                        }
                        let organization =
                            Utf8StringRef::try_from(&atav.value).unwrap();
                        let organization: &str = organization.as_ref();
                        if organization != "Oxide Computer Company" {
                            panic!("Invalid organizationName");
                        }
                    } else if atav.oid == COMMON_NAME {
                        if atav.value.tag() != Tag::Utf8String {
                            panic!("Invalid tag for Subject commonName");
                        }
                        let common =
                            Utf8StringRef::try_from(&atav.value).unwrap();
                        let common: &str = common.as_ref();
                        if let Ok(id) = PlatformId::try_from(common) {
                            if platform_id.is_none() {
                                platform_id = Some(id);
                            } else {
                                panic!(
                                    "PkiPath cannot have multiple PlatformIds"
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(platform_id)
    }
}
