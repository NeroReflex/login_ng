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

use crate::pam::mount::{MountAuthDBus, MountAuthOperations};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::test]
async fn test_new() {
    const AUTHORIZATION_TESTFILE: &str = "test_new.json";
    let filepath = Path::new("./").join(AUTHORIZATION_TESTFILE);

    if std::fs::exists(filepath.clone()).unwrap() {
        std::fs::remove_file(filepath.clone()).unwrap();
    }

    let mounts_auth_op = Arc::new(RwLock::new(MountAuthOperations::new(filepath.clone())));

    let mounts_auth = MountAuthDBus::new(mounts_auth_op.clone());

    assert!(
        !(mounts_auth
            .check("username", format!("{:X}", 0x63DE253AAu64))
            .await)
    );

    std::fs::remove_file(filepath.clone()).unwrap();
}

#[tokio::test]
async fn test_authorize() {
    const AUTHORIZATION_TESTFILE: &str = "test_authorize.json";
    let filepath = Path::new("./").join(AUTHORIZATION_TESTFILE);

    if std::fs::exists(filepath.clone()).unwrap() {
        std::fs::remove_file(filepath.clone()).unwrap();
    }

    let mounts_auth_op = Arc::new(RwLock::new(MountAuthOperations::new(filepath.clone())));

    let mut mounts_auth = MountAuthDBus::new(mounts_auth_op.clone());

    const NUM: u64 = 0x4E421u64;

    assert!(!(mounts_auth.check("username", format!("{:X}", NUM)).await));
    assert_eq!(
        mounts_auth
            .authorize("username", format!("{:X}", NUM))
            .await,
        0u32
    );
    assert!(mounts_auth.check("username", format!("{:X}", NUM)).await);

    std::fs::remove_file(filepath.clone()).unwrap();
}

#[tokio::test]
async fn test_authorize_different_users() {
    const AUTHORIZATION_TESTFILE: &str = "test_authorize_different_users.json";
    let filepath = Path::new("./").join(AUTHORIZATION_TESTFILE);

    if std::fs::exists(filepath.clone()).unwrap() {
        std::fs::remove_file(filepath.clone()).unwrap();
    }

    let mounts_auth_op = Arc::new(RwLock::new(MountAuthOperations::new(filepath.clone())));

    let mut mounts_auth = MountAuthDBus::new(mounts_auth_op.clone());

    const NUM1: u64 = 0x2913787u64;
    const NUM2: u64 = 0x4E42142u64;

    assert!(!(mounts_auth.check("username", format!("{:X}", NUM1)).await));
    assert!(!(mounts_auth.check("test", format!("{:X}", NUM2)).await));
    assert_eq!(
        mounts_auth.authorize("test", format!("{:X}", NUM2)).await,
        0u32
    );
    assert_eq!(
        mounts_auth
            .authorize("username", format!("{:X}", NUM1))
            .await,
        0u32
    );
    assert!(mounts_auth.check("username", format!("{:X}", NUM1)).await);
    assert!(mounts_auth.check("test", format!("{:X}", NUM2)).await);
    assert!(!(mounts_auth.check("test", format!("{:X}", NUM1)).await));
    assert!(!(mounts_auth.check("username", format!("{:X}", NUM2)).await));

    std::fs::remove_file(filepath.clone()).unwrap();
}

#[tokio::test]
async fn test_authorization_file() {
    const AUTHORIZATION_TESTFILE: &str = "test_authorization_file.json";
    let filepath = Path::new("./").join(AUTHORIZATION_TESTFILE);

    if std::fs::exists(filepath.clone()).unwrap() {
        std::fs::remove_file(filepath.clone()).unwrap();
    }

    // write file
    let content = "
{
    \"authorizations\": {
        \"username\": [
            \"3ED66D06576D7F05\"
        ]
    }
}";

    std::fs::write(filepath.clone(), content).unwrap();

    let mounts_auth_op = Arc::new(RwLock::new(MountAuthOperations::new(filepath.clone())));

    let mounts_auth = MountAuthDBus::new(mounts_auth_op.clone());

    const AUTH_TO_TEST: u64 = 0x3ED66D06576D7F05;

    assert!(
        mounts_auth
            .check("username", format!("{:X}", AUTH_TO_TEST))
            .await
    );
    assert!(
        !(mounts_auth
            .check("test", format!("{:X}", AUTH_TO_TEST))
            .await)
    );

    std::fs::remove_file(filepath.clone()).unwrap();
}
