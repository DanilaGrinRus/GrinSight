//! DPAPI: the key is wrapped for the current Windows user on this machine.
//!
//! This is the only module of the payment core that contains `unsafe`: two
//! calls into `crypt32.dll` and the release of the buffer they return.
#![allow(unsafe_code)]

use crate::Protector;
use core::ffi::c_void;
use std::io;
use zeroize::{Zeroize, Zeroizing};

/// `DATA_BLOB` of the Windows API.
#[repr(C)]
struct DataBlob {
    cb_data: u32,
    pb_data: *mut u8,
}

/// Never show a window; fail instead.
const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
/// Ties the blob to this use, so a blob made for something else is refused.
const ENTROPY: &[u8] = b"GrinSight Fly tail guard key v1";
/// Far above any blob this module produces.
const MAX_LEN: usize = 64 * 1024;

#[link(name = "crypt32")]
extern "system" {
    fn CryptProtectData(
        data_in: *const DataBlob,
        description: *const u16,
        entropy: *const DataBlob,
        reserved: *mut c_void,
        prompt: *mut c_void,
        flags: u32,
        data_out: *mut DataBlob,
    ) -> i32;
    fn CryptUnprotectData(
        data_in: *const DataBlob,
        description: *mut *mut u16,
        entropy: *const DataBlob,
        reserved: *mut c_void,
        prompt: *mut c_void,
        flags: u32,
        data_out: *mut DataBlob,
    ) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn LocalFree(mem: *mut c_void) -> *mut c_void;
}

/// Wraps secrets with the Windows Data Protection API for the current user.
#[derive(Clone, Copy, Debug, Default)]
pub struct Dpapi;

fn refused(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, what)
}

/// Copy the buffer DPAPI returned, wipe it and give it back to the system.
fn take(out: DataBlob) -> io::Result<Zeroizing<Vec<u8>>> {
    if out.pb_data.is_null() {
        return Err(refused("no data returned"));
    }
    let len = usize::try_from(out.cb_data).unwrap_or(usize::MAX);
    let copy = if len <= MAX_LEN {
        // SAFETY: on success the system returned a buffer of exactly
        // `cb_data` bytes at `pb_data`, owned by us until LocalFree.
        let bytes = unsafe { std::slice::from_raw_parts_mut(out.pb_data, len) };
        let copy = Zeroizing::new(bytes.to_vec());
        bytes.zeroize();
        Some(copy)
    } else {
        None
    };
    // SAFETY: the buffer was allocated by the system for this call and is
    // released exactly once; it is not used afterwards.
    unsafe {
        LocalFree(out.pb_data.cast::<c_void>());
    }
    copy.ok_or_else(|| refused("returned data is too large"))
}

fn blob(bytes: &[u8]) -> io::Result<DataBlob> {
    if bytes.len() > MAX_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "too large"));
    }
    Ok(DataBlob {
        cb_data: u32::try_from(bytes.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too large"))?,
        // the API takes a mutable pointer but only reads the input
        pb_data: bytes.as_ptr().cast_mut(),
    })
}

impl Protector for Dpapi {
    fn protect(&self, plain: &[u8]) -> io::Result<Vec<u8>> {
        let input = blob(plain)?;
        let entropy = blob(ENTROPY)?;
        let mut out = DataBlob {
            cb_data: 0,
            pb_data: core::ptr::null_mut(),
        };
        // SAFETY: `input` and `entropy` point at live slices of the stated
        // lengths for the whole call; `out` is a valid place for the result;
        // the optional arguments are null as the API allows.
        let ok = unsafe {
            CryptProtectData(
                &input,
                core::ptr::null(),
                &entropy,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(refused("the system refused to protect the key"));
        }
        Ok(take(out)?.to_vec())
    }

    fn unprotect(&self, wrapped: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        let input = blob(wrapped)?;
        let entropy = blob(ENTROPY)?;
        let mut out = DataBlob {
            cb_data: 0,
            pb_data: core::ptr::null_mut(),
        };
        // SAFETY: as in `protect`; the description is not requested.
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                core::ptr::null_mut(),
                &entropy,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        };
        if ok == 0 {
            return Err(refused("the key was protected by another user or machine"));
        }
        take(out)
    }
}
