// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::Error;
use attest_data::{Log, Measurement, Sha3_256Digest};
use camino::Utf8PathBuf;
use const_oid::{AssociatedOid, ObjectIdentifier};
use der::{
    asn1::OctetString, Decode, DecodeValue, Header, Sequence, SliceReader,
};
use rats_corim::Corim;
use std::collections::HashSet;

use sha3::Sha3_256;
use x509_cert::PkiPath;

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

pub fn measure_from_corpus(corpus: &Vec<Utf8PathBuf>) -> Result<(), Error> {
    let corpus = crate::measurements::corim_to_set(corpus)?;

    let ipcc = crate::ipcc::Ipcc::new().map_err(crate::Error::RotRequest)?;
    // XXX error handling what is it lol
    let log = ipcc.get_measurement_log().unwrap();
    let certs = ipcc.get_certificates().unwrap();

    let measurements = crate::measurements::artifacts_to_set(&certs, &log)?;

    if !measurements.is_subset(&corpus) {
        panic!("Your measurements are wrong :(");
    }

    Ok(())
}
