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

pub mod disk;
pub mod mount;
pub mod result;
pub mod security;
pub mod session;

pub const XDG_RUNTIME_DIR_PATH: &str = "/tmp/xdg/";

use zbus::Error as ZError;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("Permission error: not running as the root user")]
    MissingPrivilegesError,

    #[error("DBus error: {0}")]
    ZbusError(#[from] ZError),

    #[error("I/O error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("pkcs1 error: {0}")]
    PKCS1Error(#[from] rsa::pkcs1::Error),

    #[error("Failed to deserialize JSON: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),
}
