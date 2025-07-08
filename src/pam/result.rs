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

use std::fmt;

#[derive(Clone, Copy, PartialEq, Debug)]
#[repr(C)]
pub enum ServiceOperationResult {
    Ok = 0,
    PubKeyError = 1,
    DataDecryptionFailed = 2,
    CannotLoadUserMountError = 3,
    MountError = 4,
    SessionAlreadyOpened = 5,
    SessionAlreadyClosed = 6,
    CannotIdentifyUser = 7,
    EmptyPubKey = 8,
    EncryptionError = 9,
    UnauthorizedMount = 10,
    SerializationError = 11,
    IOError = 12,
    Unknown,
}

impl fmt::Display for ServiceOperationResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let result_str = match self {
            ServiceOperationResult::Ok => "Ok",
            ServiceOperationResult::PubKeyError => "Public Key Error",
            ServiceOperationResult::DataDecryptionFailed => "Data Decryption Failed",
            ServiceOperationResult::CannotLoadUserMountError => "Cannot Load User Mount",
            ServiceOperationResult::MountError => "Mount Error",
            ServiceOperationResult::SessionAlreadyOpened => "Session Already Opened",
            ServiceOperationResult::SessionAlreadyClosed => "Session Already Closed",
            ServiceOperationResult::CannotIdentifyUser => "Cannot Identify User",
            ServiceOperationResult::EmptyPubKey => "Empty Public Key",
            ServiceOperationResult::EncryptionError => "Encryption error",
            ServiceOperationResult::UnauthorizedMount => "Unauthorized mount attempted",
            ServiceOperationResult::SerializationError => "(De)Serialization error",
            ServiceOperationResult::IOError => "I/O Error",
            ServiceOperationResult::Unknown => "Unknown Error",
        };
        write!(f, "{}", result_str)
    }
}

impl From<ServiceOperationResult> for u32 {
    fn from(val: ServiceOperationResult) -> Self {
        val as u32
    }
}

impl From<u32> for ServiceOperationResult {
    fn from(value: u32) -> Self {
        match value {
            0 => ServiceOperationResult::Ok,
            1 => ServiceOperationResult::PubKeyError,
            2 => ServiceOperationResult::DataDecryptionFailed,
            3 => ServiceOperationResult::CannotLoadUserMountError,
            4 => ServiceOperationResult::MountError,
            5 => ServiceOperationResult::SessionAlreadyOpened,
            6 => ServiceOperationResult::SessionAlreadyClosed,
            7 => ServiceOperationResult::CannotIdentifyUser,
            8 => ServiceOperationResult::EmptyPubKey,
            9 => ServiceOperationResult::EncryptionError,
            10 => ServiceOperationResult::UnauthorizedMount,
            11 => ServiceOperationResult::SerializationError,
            12 => ServiceOperationResult::IOError,
            _ => ServiceOperationResult::Unknown,
        }
    }
}
