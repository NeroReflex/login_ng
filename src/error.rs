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

use aes_gcm::Error as AesError;
use std::io::Error as IoError;

use thiserror::Error;

use crate::user::UserAuthDataError;

#[derive(Debug, Error)]
pub enum UserOperationError {
    #[error("File I/O error: {0}")]
    Io(#[from] IoError),
    #[error("Encryption error: {0}")]
    EncryptionError(/*#[from]*/ AesError),
    #[error("Hashing error: {0}")]
    HashingError(#[from] bcrypt::BcryptError),
    #[error("login-ng error: {0}")]
    User(#[from] UserAuthDataError),
}
