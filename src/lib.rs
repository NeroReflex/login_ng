/*
    login-ng A greeter written in rust that also supports autologin with systemd-homed
    Copyright (C) 2024-2025  Denis Benato

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

pub mod auth;
pub mod command;
pub mod environment;
pub mod error;
pub mod interactions;
pub mod mount;
pub mod pam;
pub mod storage;
pub mod user;

pub extern crate aes_gcm;
pub extern crate pam as pam_binding;
pub extern crate rand;
pub extern crate rs_sha512;
pub extern crate rsa;
pub extern crate serde;
pub extern crate serde_json;
pub extern crate users;
pub extern crate zbus;

#[cfg(test)]
pub(crate) mod tests;

extern crate bytevec2;

pub const DEFAULT_XATTR_NAME: &str = "user.login-ng";

use std::ffi::OsString;

use hkdf::*;
use sha2::Sha256;
use users::{os::unix::UserExt, User};

pub const LIBRARY_VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) fn derive_key(input: &str, salt: &[u8]) -> [u8; 32] {
    // Create an HKDF instance with SHA-256 as the hash function
    let hkdf = Hkdf::<Sha256>::new(Some(salt), input.as_bytes());

    // Prepare a buffer for the derived key
    let mut okm = [0u8; 32]; // Output key material (32 bytes)

    // Extract the key material
    hkdf.expand(&[], &mut okm).expect("Failed to expand key");

    okm
}

pub(crate) fn password_to_vec(password: &String) -> Vec<u8> {
    password.as_str().into()
}

pub(crate) fn vec_to_password(vec: &Vec<u8>) -> String {
    String::from_utf8_lossy(vec.as_slice()).to_string()
}

// this MUST be implemented and used because entering invalid strings can be a security hole (see lossy_utf8)
pub(crate) fn is_valid_password(password: &String) -> bool {
    vec_to_password(password_to_vec(password).as_ref()) == password.clone()
}

pub fn valid_users() -> Vec<User> {
    unsafe { crate::users::all_users() }
        .filter_map(|user| {
            if user.name() == "nobody" {
                return None;
            }

            if user.shell() == OsString::from("/bin/false") {
                return None;
            }

            let uid = user.uid();
            if uid == 0 || uid < 1000 || uid == crate::users::uid_t::MAX {
                return None;
            }

            Some(user)
        })
        .collect()
}
