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

use tokio::{
    sync::{Mutex, RwLock},
    task::spawn,
};
use zbus::interface;

use sys_mount::{Mount, UnmountDrop};

use crate::{
    storage::{load_user_mountpoints, StorageSource},
    users::{get_user_by_name, gid_t, os::unix::UserExt, uid_t},
};

use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    ffi::OsString,
    ops::DerefMut,
    sync::Arc,
};
use std::{
    hash::{Hash, Hasher},
    path::PathBuf,
};

use crate::{
    pam::{
        disk::read_file_or_create_default,
        mount::{mount_all, MountAuthOperations},
        result::*,
        security::*,
        ServiceError,
    },
    rsa::{
        pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding},
        RsaPrivateKey, RsaPublicKey,
    },
};

struct UserSession {
    _mounts: Vec<UnmountDrop<Mount>>,
    count: usize,
}

enum RsaPrivateKeyFetchOpStatus {
    Ready(Arc<RsaPrivateKey>),
    InProgress(tokio::task::JoinHandle<Result<RsaPrivateKey, ServiceError>>),
}

pub struct Sessions {
    mounts_auth: Arc<RwLock<MountAuthOperations>>,
    priv_key: Mutex<RsaPrivateKeyFetchOpStatus>,
    one_time_tokens: HashMap<u64, Vec<u8>>,
    sessions: HashMap<OsString, UserSession>,
}

impl Sessions {
    pub fn new(
        private_key_file_path: PathBuf,
        mounts_auth: Arc<RwLock<MountAuthOperations>>,
    ) -> Self {
        let file_path = private_key_file_path;

        let filepath = file_path.clone();

        let priv_key = Mutex::new(RsaPrivateKeyFetchOpStatus::InProgress(spawn(async {
            let default_key_gen_fn = || {
                let mut rng = crate::rand::thread_rng();
                let priv_key = crate::rsa::RsaPrivateKey::new(&mut rng, 4096)
                    .expect("failed to generate a key");

                Ok(priv_key.to_pkcs1_pem(LineEnding::CRLF).unwrap().to_string())
            };

            let key_as_str = read_file_or_create_default(filepath, default_key_gen_fn).await?;

            RsaPrivateKey::from_pkcs1_pem(key_as_str.as_str()).map_err(ServiceError::PKCS1Error)
        })));

        let one_time_tokens = HashMap::new();
        let sessions = HashMap::new();

        Self {
            mounts_auth,
            priv_key,
            one_time_tokens,
            sessions,
        }
    }

    async fn fetch_priv_key(&mut self) -> Result<Arc<RsaPrivateKey>, ServiceError> {
        let mut lck = self.priv_key.lock().await;
        match lck.deref_mut() {
            RsaPrivateKeyFetchOpStatus::Ready(rsa_private_key) => Ok(rsa_private_key.clone()),
            RsaPrivateKeyFetchOpStatus::InProgress(join_handle) => match join_handle.await {
                Ok(completed) => {
                    let new_key = Arc::new(completed?);
                    *lck = RsaPrivateKeyFetchOpStatus::Ready(new_key.clone());
                    Ok(new_key)
                }
                Err(err) => {
                    println!("❌ Error awaiting for private key fetch task: {err}");
                    Err(ServiceError::JoinError(err))
                }
            },
        }
    }
}

#[interface(
    name = "org.neroreflex.login_ng_session1",
    proxy(
        default_service = "org.neroreflex.login_ng_session",
        default_path = "/org/neroreflex/login_ng_session"
    )
)]
impl Sessions {
    async fn initiate_session(&mut self) -> String {
        println!("🔓 Requested initialization of a new session");

        let priv_key = match self.fetch_priv_key().await {
            Ok(priv_key) => priv_key,
            Err(err) => {
                println!("❌ Error fetching the private RSA key: {err}");
                return String::new();
            }
        };

        let pub_pkcs1_pem =
            match RsaPublicKey::from(priv_key.as_ref()).to_pkcs1_pem(LineEnding::CRLF) {
                Ok(key) => key,
                Err(err) => {
                    println!("❌ Error serializing the RSA key: {err}");
                    return String::new();
                }
            };

        let session = SessionPrelude::new(pub_pkcs1_pem);

        let otp = session.one_time_token();

        let mut hasher = DefaultHasher::new();
        otp.hash(&mut hasher);
        let key = hasher.finish();

        let serialized = match serde_json::to_string(&session) {
            Ok(serialized) => serialized,
            Err(err) => {
                println!("❌ Error serializing the session one time token: {err}");
                return String::new();
            }
        };

        self.one_time_tokens.insert(key, otp);

        println!("✅ Created one time token {key}");

        serialized
    }

    async fn open_user_session(
        &mut self,
        username: &str,
        password: Vec<u8>,
    ) -> (u32, uid_t, gid_t) {
        println!("👤 Requested session for user '{username}' to be opened");

        let source = StorageSource::Username(String::from(username));

        let Some(user) = get_user_by_name(username) else {
            return (ServiceOperationResult::CannotIdentifyUser.into(), 0, 0);
        };

        match self.sessions.get_mut(&user.name().to_os_string()) {
            Some(session) => {
                session.count += 1;

                println!("✅ Incremented count of sessions for user {username}");
            }
            None => {
                let priv_key = match self.fetch_priv_key().await {
                    Ok(priv_key) => priv_key,
                    Err(err) => {
                        println!("❌ Error fetching the private RSA key: {err}");
                        return (ServiceOperationResult::PubKeyError.into(), 0, 0);
                    }
                };

                let (otp, password) = match SessionPrelude::decrypt(priv_key.clone(), password) {
                    Ok(result) => result,
                    Err(err) => {
                        eprintln!("❌ Error in decrypting data: {err}");
                        return (ServiceOperationResult::DataDecryptionFailed.into(), 0, 0);
                    }
                };

                // check the OTP to be available to defeat replay attacks
                let mut hasher = DefaultHasher::new();
                otp.hash(&mut hasher);
                match self.one_time_tokens.remove(&hasher.finish()) {
                    Some(stored) => {
                        if stored != otp {
                            eprintln!("🚫 The provided temporary OTP key couldn't be verified");
                            return (ServiceOperationResult::EncryptionError.into(), 0, 0);
                        }
                    }
                    None => {
                        println!("❌ Error in finding the provided temporary OTP key");
                        return (ServiceOperationResult::EncryptionError.into(), 0, 0);
                    }
                }

                let user_mounts = match load_user_mountpoints(&source) {
                    Ok(user_cfg) => user_cfg,
                    Err(err) => {
                        eprintln!("❌ Error loading user mount data: {err}");
                        return (
                            ServiceOperationResult::CannotLoadUserMountError.into(),
                            0,
                            0,
                        );
                    }
                };

                // Check for the mount to be approved by root
                // otherwise the user might mount everything he wants to
                // with every dmask, potentially compromising the
                // security and integrity of the whole system.
                if let Some(mounts) = user_mounts.clone() {
                    let hash_to_check = mounts.hash();
                    match self.mounts_auth.read().await.read_auth_file().await {
                        Ok(mounts_auth) => {
                            if !mounts_auth.authorized(username, hash_to_check.clone()) {
                                eprintln!(
                                    "🚫 User {username} attempted an unauthorized mount {hash_to_check}."
                                );
                                return (ServiceOperationResult::UnauthorizedMount.into(), 0, 0);
                            }
                        }
                        Err(err) => {
                            eprintln!("❌ Error reading mount authorizations file: {err}");
                            return (ServiceOperationResult::UnauthorizedMount.into(), 0, 0);
                        }
                    };
                };

                let mounted_devices = mount_all(
                    user_mounts,
                    password,
                    user.uid(),
                    user.primary_group_id(),
                    user.name().to_string_lossy().to_string(),
                    user.home_dir().as_os_str().to_string_lossy().to_string(),
                );

                if mounted_devices.is_empty() {
                    eprintln!("❌ Error mounting one or more devices for user {username}");
                    return (ServiceOperationResult::MountError.into(), 0, 0);
                }

                let user_session = UserSession {
                    _mounts: mounted_devices,
                    count: 1,
                };

                self.sessions
                    .insert(user.name().to_os_string(), user_session);

                println!("✅ Successfully opened session for user {username}");
            }
        }

        (
            ServiceOperationResult::Ok.into(),
            user.uid(),
            user.primary_group_id(),
        )
    }

    async fn close_user_session(&mut self, user: &str) -> u32 {
        println!("👤 Requested session for user '{user}' to be closed");

        let Some(user) = get_user_by_name(user) else {
            return ServiceOperationResult::CannotIdentifyUser.into();
        };

        let username = user.name().to_string_lossy();

        match self.sessions.get_mut(user.name()) {
            Some(session) => {
                session.count -= 1;
                if session.count == 0 {
                    // due to how directories are mounted discarding the session also umounts all mount points:
                    // either remove the user session from the collection and destroy the session or
                    // report to the caller that the requested session is already closed
                    match self.sessions.remove(user.name()) {
                        Some(user_session) => drop(user_session),
                        None => return ServiceOperationResult::SessionAlreadyClosed.into(),
                    };
                }

                println!("✅ Successfully closed session for user '{username}'");

                ServiceOperationResult::Ok.into()
            }
            None => {
                eprintln!("❌ Error closing session for user {username}: already closed");

                ServiceOperationResult::SessionAlreadyClosed.into()
            }
        }
    }
}
