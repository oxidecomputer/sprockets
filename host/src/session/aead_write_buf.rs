// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Wrappers around a buffer for storing plaintext and ciphertext data for use
//! with AEAD algorithms.
//!
//! The buffer reserves space at the beginning for a 4-byte length header, and
//! enough data at the end to store an AEAD authentication tag. This allows the
//! 4 byte framed encrypted data + tag to be sent with one call to the underlying IO
//! system.
//!
//! Plaintext data can be written into the buffer until it is full, at which
//! point the data can be encrypted in place and extended with an authentication
//! tag. Once encrypted, the size header is filled in, and the buffer is
//! "sealed" as an `AeadCiphertextBuf`.

// The location where plaintext/ciphertext start inside `AeadPlaintextBuf` and
// `AeadCiphertextBuf`.
const DATA_START: usize = 4;
use super::TAG_SIZE;
use sprockets_session::Tag;

/// An extensible buffer storing plaintext data for use with an AEAD algorithm
pub struct AeadPlaintextBuf {
    // The entire buffer with a 4 byte size header and TAG_SIZE data at the end.
    buf: Box<[u8]>,

    // The amount of currently written user data to the buffer. This is the size
    // of the unencrypted and encrypted data not including the authentication tag.
    written: usize,
}

impl AeadPlaintextBuf {
    /// The total capacity of the underlying buffer is:
    /// 4 + data_cap + TAG_SIZE
    pub fn with_capacity(data_cap: usize) -> Self {
        // Ensure the max chunk size won't overflow our u32 length prefix.
        assert!(data_cap + TAG_SIZE <= u32::MAX as usize);

        AeadPlaintextBuf {
            buf: vec![0; DATA_START + data_cap + TAG_SIZE].into_boxed_slice(),
            written: 0,
        }
    }

    // The capacity of the plaintext buffer
    //
    // This does not include the 4 byte size header or TAG_SIZE
    pub fn capacity(&self) -> usize {
        self.buf.len() - DATA_START - TAG_SIZE
    }

    // The amount of room left in the user data buffer
    pub fn remaining(&self) -> usize {
        self.capacity() - self.written
    }

    pub fn is_full(&self) -> bool {
        self.remaining() == 0
    }

    pub fn is_empty(&self) -> bool {
        self.written == 0
    }

    // Copy as much data as we can from `buf` into `self.buf`.
    //
    // Return the number of bytes copied.
    pub fn extend(&mut self, buf: &[u8]) -> usize {
        let n = usize::min(self.remaining(), buf.len());
        let start = DATA_START + self.written;
        self.buf[start..start + n].copy_from_slice(&buf[..n]);
        self.written += n;
        n
    }

    // Encrypt all plaintext data in the buffer, append the authentication tag,
    // and write the size header.
    //
    // Return the ciphertext on success and `self` if encryption fails.
    pub fn encrypt<F>(mut self, encrypt: F) -> Result<AeadCiphertextBuf, Self>
    where
        F: FnOnce(&mut [u8]) -> Result<Tag, ()>,
    {
        // Need a match to appease the borrow checker
        let tag = match encrypt(self.plaintext_mut_slice()) {
            Ok(tag) => tag,
            Err(()) => return Err(self),
        };
        self.tag_mut_slice().copy_from_slice(&tag);
        // This is guaranteed to fit in a u32 from the asserted invariant in
        // `with_capacity`.
        let len = u32::try_from(self.written + TAG_SIZE).unwrap();
        self.buf[..DATA_START].copy_from_slice(&len.to_be_bytes());
        Ok(AeadCiphertextBuf {
            buf: self.buf,
            written: self.written,
        })
    }

    // Return the a mutable slice where the tag should be written
    fn tag_mut_slice(&mut self) -> &mut [u8] {
        let start = DATA_START + self.written;
        let end = start + TAG_SIZE;
        &mut self.buf[start..end]
    }

    // Return the mutable slice of the written plaintext
    fn plaintext_mut_slice(&mut self) -> &mut [u8] {
        let end = DATA_START + self.written;
        &mut self.buf[DATA_START..end]
    }
}

// A "sealed" buffer containing ciphertext and AEAD authentication tag, prefixed
// with the length of both, and possibly unused free space at the end.
//
// The filled part of the buffer can be treated as an application level `frame`
// for an encrypted protocol.
pub struct AeadCiphertextBuf {
    buf: Box<[u8]>,

    // The amount of ciphertext written into buf
    written: usize,
}

impl AeadCiphertextBuf {
    // Return the entire frame as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len()]
    }

    // Return the length of the frame
    pub fn len(&self) -> usize {
        DATA_START + self.written + TAG_SIZE
    }
}

impl From<AeadCiphertextBuf> for AeadPlaintextBuf {
    fn from(buf: AeadCiphertextBuf) -> Self {
        AeadPlaintextBuf {
            buf: buf.buf,
            written: 0,
        }
    }
}
