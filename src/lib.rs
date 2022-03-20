// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), no_std)]

pub mod endorsements;
pub mod keys;
pub mod measurements;
pub mod msgs;
pub mod rot;

#[cfg(test)]
mod tests {
    #[test]
    fn rot_to_sp() {}
}
