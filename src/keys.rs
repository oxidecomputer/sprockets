// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.use derive_more::From;

use derive_more::From;
use hubpack::SerializedSize;
use serde::{Deserialize, Serialize};
use serde_big_array::big_array;

// Macro must be invoked to provide big array support for serde
big_array! { BigArray; }

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct Ed25519PublicKey([u8; 32]);

#[derive(Debug, PartialEq, Eq)]
pub struct Ed25519SecretKey([u8; 32]);

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct Ed25519Signature(#[serde(with = "BigArray")] [u8; 64]);

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct Sha256Digest([u8; 32]);

#[derive(Debug, Copy, Clone, PartialEq, Eq, From, Serialize, Deserialize, SerializedSize)]
pub struct Nonce([u8; 32]);
