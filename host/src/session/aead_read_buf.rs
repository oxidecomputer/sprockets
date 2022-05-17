// This Source Code Plaintextubject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Wrappers around a buffer for storing plaintext and ciphertext data for use
//! with AEAD algorithms.
//!
//! The buffer reserves space at the beginning for a 4-byte length header, and
//! enough data at the end to store an AEAD authentication tag. This allows the
//! 4 byte framed encrypted data + tag to be read into a single buffer.
//!
//! Ciphertext is buffered until a complete frame is read. Because read calls
//! may read data from the next frame, this data may be buffered as well. When a
//! complete fPlaintextecrypted, any extra data from the next frame is shifted
//! to the beginning of the buffer.

use std::cell::Cell;
use std::io;
use std::ops::Range;

// The location wPlaintextntext/ciphertext start inside `AeadPlaintextBuf` and
// `AeadCiphertextBuf`.
const DATA_START: usize = 4;
use super::TAG_SIZE;
use sprockets_session::Tag;

/// A buffer to in which to read ciphertext data with a 4 byte frame header, and trailing
/// authentication tag.
///
/// When a complete frame is read, the frame will be decrypted and the type will
/// convert into a DecryptedFrameBuf.
pub struct AeadCiphertextFrameBuf {
    // A buffer capable of storing a maximum sized frame including size header
    // and authentication tag.
    buf: Box<[u8]>,

    // The number of bytes read into the buffer so far
    read_pos: usize,

    // The length of the frame read from the frame header (not including the
    // header).
    //
    // Only valid once the 4-byte frame header has been read.
    frame_length: Cell<Option<usize>>,
}

impl AeadCiphertextFrameBuf {
    /// The total capacity of the underlying buffer is:
    /// 4 + cap + TAG_SIZE
    pub fn with_capacity(cap: usize) -> Self {
        // Ensure the max chunk size won't overflow our u32 length prefix.
        assert!(cap + TAG_SIZE <= u32::MAX as usize);

        AeadCiphertextFrameBuf {
            buf: vec![0; DATA_START + cap + TAG_SIZE].into_boxed_slice(),
            read_pos: 0,
            frame_length: Cell::new(None),
        }
    }

    /// Advance the read cursor of the underlying buffer after the user has read
    /// data into it.
    pub fn advance(&mut self, n: usize) {
        self.read_pos += n;
        assert!(self.read_pos <= self.buf.len());
    }

    /// Return a mutable slice of free space at the end of the buffer
    pub fn unfilled_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.read_pos..]
    }

    // Return the amount of free space at the end of the buffer
    // Only used in tests
    #[allow(dead_code)]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.read_pos
    }

    /// Return `Ok(true)` if at least a full frame has been read into
    /// the buffer and `Ok(false) if reading is incomplete.
    ///
    /// Return an error it the size in the header is invalid.
    pub fn ready_to_decrypt(&self) -> io::Result<bool> {
        if self.read_pos < DATA_START {
            return Ok(false);
        }

        // Check the cached value
        let len = if let Some(len) = self.frame_length.get() {
            len
        } else {
            let len =
                u32::from_be_bytes(self.buf[..DATA_START].try_into().unwrap())
                    as usize;

            // Fail on frames longer than our capacity or too short to contain
            // an auth tag and at least one byte of data.
            if len + DATA_START > self.buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "total frame length ({}) exceeds read buffer size ({})",
                        len + DATA_START,
                        self.buf.len()
                    ),
                ));
            } else if len <= TAG_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("frame length ({len}) too short"),
                ));
            }
            self.frame_length.set(Some(len));
            len
        };

        if self.read_pos >= len + DATA_START {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    // Decrypt a frame in place.
    //
    // Return a `Ok(DecryptedFrameBuf)` upon success and `Err(Self)` if
    // decryption fails.
    //
    // Panics if the frame is not ready to decrypt.
    pub fn decrypt_frame<F>(
        mut self,
        decrypt: F,
    ) -> Result<AeadPlaintextFrameBuf, Self>
    where
        F: FnOnce(&mut [u8], &Tag) -> Result<(), ()>,
    {
        let len = self.frame_length.get().unwrap();
        assert!(self.read_pos >= len + DATA_START);

        let frame_end = DATA_START + len;
        let ciphertext_end = frame_end - TAG_SIZE;

        // Split into the ciphertext and tag, skipping over the frame prefix
        let bytes = &mut self.buf[DATA_START..frame_end];
        let (ciphertext, tag) = bytes.split_at_mut(len - TAG_SIZE);

        // Need a match to appease the borrow checker
        match decrypt(ciphertext, Tag::from_slice(tag)) {
            Ok(()) => Ok(AeadPlaintextFrameBuf {
                buf: self.buf,
                plaintext: DATA_START..ciphertext_end,
                extra: frame_end..self.read_pos,
            }),
            Err(()) => Err(self),
        }
    }
}

/// A buffer containing a decrypted frame, and possibly extra data from the next
/// frame at the end of the buffer.
///
/// When all the decrypted data is read out of the buffer, the extra data will
/// be shifted to the beginning of the buffer and the type will convert into
/// an AeadCiphertextFrameBuf.
pub struct AeadPlaintextFrameBuf {
    buf: Box<[u8]>,
    plaintext: Range<usize>,
    extra: Range<usize>,
}

impl AeadPlaintextFrameBuf {
    // Return the remainder of unread plaintext data of the frame
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[self.plaintext.start..self.plaintext.end]
    }

    // Return the length of the remaining plaintext to be copied
    pub fn num_bytes_to_copy(&self) -> usize {
        self.plaintext.end - self.plaintext.start
    }

    // Advance the start of the plaintext slice to reflect data that has already
    // been read.
    pub fn advance(&mut self, n: usize) {
        self.plaintext.start += n;
        assert!(self.plaintext.start <= self.plaintext.end);
    }

    pub fn is_empty(&self) -> bool {
        self.plaintext.is_empty()
    }
}

impl From<AeadPlaintextFrameBuf> for AeadCiphertextFrameBuf {
    fn from(mut buf: AeadPlaintextFrameBuf) -> Self {
        // Shift the ciphertext at the end of the buffer to byte 0
        //
        // TODO-perf: We could consider not shifting if we already
        // have all (or part but know we'd have enough room for the
        // rest) of the next encrypted chunk, but it would make
        // our logic a fair bit more complicated. For now we always
        // shift down after finishing a chunk.
        buf.buf.copy_within(buf.extra.clone(), 0);

        AeadCiphertextFrameBuf {
            buf: buf.buf,
            read_pos: buf.extra.end - buf.extra.start,
            frame_length: Cell::new(None),
        }
    }
}
