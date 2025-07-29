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

use crate::users;
use sys_mount::{Mount, Unmount, UnmountDrop, UnmountFlags};

use crate::mount::MountPoints;
use tokio::sync::RwLock;

use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::{fs::create_dir, path::Path};

use std::io::{self, Write};

use serde::{Deserialize, Serialize};
use serde_json;

use crate::pam::{
    result::ServiceOperationResult,
    {disk, ServiceError},
};

use zbus::interface;

use tokio::time::{sleep, Duration};

/// Mounts a filesystem at the specified path.
///
/// This function takes a tuple containing information necessary for mounting a filesystem.
/// It checks if the specified mount path exists and is a directory. If the path does not exist,
/// it attempts to create it. Depending on whether the filesystem type is provided, it constructs
/// a mount operation accordingly.
///
/// # Parameters
///
/// - `data`: A tuple of four `String` values:
///   - `data.0`: The filesystem type (e.g., "ext4", "nfs"). If this is an empty string, the mount
///     operation will be performed without specifying a filesystem type.
///   - `data.1`: Additional data required for the mount operation (e.g., options for the mount).
///   - `data.2`: The source of the filesystem to mount (e.g., a device or remote filesystem).
///   - `data.3`: The target directory where the filesystem should be mounted.
///
/// # Returns
///
/// Returns a `Result<Mount, io::Error>`. On success, it returns a `Mount` object representing
/// the mounted filesystem. On failure, it returns an `io::Error` indicating what went wrong,
/// which could include issues with directory creation or mounting the filesystem.
///
/// # Errors
///
/// This function may fail if:
/// - The specified mount path does not exist and cannot be created due to permission issues.
/// - The mount operation fails due to invalid parameters or system errors.
///
fn mount<PATH>(data: (String, String, String, PATH)) -> io::Result<Mount>
where
    PATH: AsRef<Path>,
{
    let mount_path = Path::new(data.3.as_ref());
    if !mount_path.exists() || !mount_path.is_dir() {
        // if the path is a file this will fail
        create_dir(mount_path)?;
    }

    match data.0.is_empty() {
        true => Mount::builder().mount(data.2.as_str(), mount_path.as_os_str()),
        false => Mount::builder()
            .fstype(data.0.as_str())
            .data(data.1.as_str())
            .mount(data.2.as_str(), data.3.as_ref()),
    }
}

pub(crate) fn mount_xdg(
    uid: users::uid_t,
    gid: users::gid_t,
    username: &str,
) -> Option<UnmountDrop<Mount>> {
    let xdg_path = PathBuf::from(crate::pam::XDG_RUNTIME_DIR_PATH);
    if !xdg_path.exists() {
        if let Err(err) = fs::create_dir(xdg_path.clone()) {
            eprintln!("❌ Error creating the xdg base path: {err}");
            return None;
        }
    } else if !xdg_path.is_dir() {
        eprintln!("🚫 Failed to use xdg base path: not a directory");
        return None;
    }

    let user_xdg_path = xdg_path.join(format!("{uid}"));
    if !user_xdg_path.exists() {
        if let Err(err) = fs::create_dir(user_xdg_path.clone()) {
            eprintln!("❌ Error creating the xdg path for user {username}: {err}");
            return None;
        }
    } else if !xdg_path.is_dir() {
        eprintln!("🚫 Failed to use xdg path for user {username}: not a directory");
        return None;
    }

    let mount_data = (
        "tmpfs".to_string(),
        format!("uid={uid},gid={gid}"),
        "tmpfs".to_string(),
        user_xdg_path.as_os_str(),
    );
    match mount(mount_data) {
        Ok(mount) => Some(mount.into_unmount_drop(UnmountFlags::DETACH)),
        Err(err) => {
            eprintln!(
                "❌ Error mounting the xdg path for user {username} ({}): {err}",
                user_xdg_path.as_os_str().to_string_lossy()
            );
            None
        }
    }
}

fn set_directory_permissions(path: &str, mode: u32) -> std::io::Result<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions)
}

fn change_owner(path: &str, uid: users::uid_t, gid: users::gid_t) -> Result<(), std::ffi::c_int> {
    let Ok(c_path) = CString::new(path) else {
        return Err(-libc::EINVAL);
    };

    if unsafe { libc::chown(c_path.as_ptr(), uid, gid) } != 0 {
        return Err(unsafe { *libc::__errno_location() });
    }

    Ok(())
}

pub(crate) fn mount_all(
    mounts: Option<MountPoints>,
    password: Vec<u8>,
    uid: users::uid_t,
    gid: users::gid_t,
    username: String,
    homedir: String,
) -> Vec<UnmountDrop<Mount>> {
    let Some(xdg_mounted_dir) = mount_xdg(uid, gid, username.as_str()) else {
        return vec![];
    };

    // mount xdg folder first
    let mut mounted_devices = vec![xdg_mounted_dir];

    let Some(mounts) = mounts else {
        return mounted_devices;
    };

    for m in mounts
        .foreach(|a, b| {
            (
                b.fstype().clone(),
                b.flags().join(",").clone(),
                b.device().clone(),
                a.clone(),
            )
        })
        .iter()
    {
        let dev = m.2.as_str();
        let path = m.3.as_str();
        match mount(m.clone()) {
            Ok(mount) => {
                println!("🟢 Mounted device {dev} into {path} for user '{username}'",);

                // Make the mount temporary, so that it will be unmounted on drop.
                mounted_devices.push(mount.into_unmount_drop(UnmountFlags::DETACH));
            }
            Err(err) => {
                eprintln!("❌ Error mounting device {dev} into {path}: {err}");

                return vec![];
            }
        }
    }

    match mount((
        mounts.mount().fstype().clone(),
        mounts.mount().flags().join(","),
        mounts.mount().device().clone(),
        homedir.clone(),
    )) {
        Ok(mount) => {
            let dev = mounts.mount().device().clone();
            let path = homedir.as_str();

            println!("🟢 Mounted device {dev} on home directory for user '{username}'",);

            if let Err(err) = set_directory_permissions(path, 0o700) {
                eprintln!("❌ Error setting permissions of {path}: {err}");
            } else if let Err(err) = change_owner(path, uid, gid) {
                eprintln!("⚠️ Error changing owner of {path} to user '{username}': {err}");
            } else {
                println!("🟢 Changed owner of {path} to user '{username}'");
            }

            // Make the mount temporary, so that it will be unmounted on drop.
            mounted_devices.push(mount.into_unmount_drop(UnmountFlags::DETACH));
        }
        Err(err) => {
            eprintln!("❌ Error mounting user directory: {err}");
            return vec![];
        }
    }

    mounted_devices
}

#[derive(Serialize, Deserialize, Default, Clone, PartialEq, Debug)]
pub struct MountAuth {
    authorizations: HashMap<String, Vec<String>>,
}

impl MountAuth {
    pub fn new(json_str: &str) -> Result<Self, ServiceError> {
        let auth: MountAuth = serde_json::from_str(json_str)?;
        Ok(auth)
    }

    pub fn load_from_file(file_path: &str) -> Result<Self, ServiceError> {
        let json_str = std::fs::read_to_string(file_path)?;
        Self::new(&json_str)
    }

    pub fn add_authorization(&mut self, username: &str, hash: String) {
        self.authorizations
            .entry(String::from(username))
            .or_default()
            .push(hash);
    }

    pub fn authorized(&self, username: &str, hash: String) -> bool {
        match self.authorizations.get(&String::from(username)) {
            Some(values) => values.contains(&hash),
            None => false,
        }
    }
}

pub struct MountAuthOperations {
    file_path: PathBuf,
}

impl MountAuthOperations {
    pub fn new(file_path: PathBuf) -> Self {
        Self { file_path }
    }

    pub(crate) async fn read_auth_file(&self) -> Result<MountAuth, ServiceError> {
        match disk::read_file_or_create_default(self.file_path.clone(), || {
            serde_json::to_string_pretty(&MountAuth::default()).map_err(ServiceError::JsonError)
        })
        .await
        {
            Ok(auth_str) => MountAuth::new(auth_str.as_str()),
            Err(err) => Err(err),
        }
    }

    pub(crate) async fn write_auth_file(
        &mut self,
        authorizations: &MountAuth,
    ) -> Result<(), ServiceError> {
        let mut file = match File::create(self.file_path.as_path()) {
            Ok(file) => file,
            Err(err) => return Err(ServiceError::IOError(err)),
        };

        if let Err(err) =
            file.write((serde_json::to_string_pretty(authorizations).unwrap() + "\n").as_bytes())
        {
            return Err(ServiceError::IOError(err));
        }

        if let Err(err) = file.flush() {
            return Err(ServiceError::IOError(err));
        }

        Ok(())
    }
}

pub struct MountAuthDBus {
    auth_mount_op: Arc<RwLock<MountAuthOperations>>,
}

impl MountAuthDBus {
    pub fn new(auth_mount_op: Arc<RwLock<MountAuthOperations>>) -> Self {
        Self { auth_mount_op }
    }
}

#[interface(
    name = "org.neroreflex.login_ng_mount1",
    proxy(
        default_service = "org.neroreflex.login_ng_mount",
        default_path = "/org/neroreflex/login_ng_mount"
    )
)]
impl MountAuthDBus {
    pub async fn authorize(&mut self, username: &str, hash: String) -> u32 {
        println!("⚙️ Requested add authorization to mount {hash} for user {username}");

        {
            let mut lck = self.auth_mount_op.write().await;
            let mut authorizations = match lck.read_auth_file().await {
                Ok(auth_str) => auth_str,
                Err(err) => {
                    eprintln!("❌ Error opening mount authorizations file: {err}");
                    return ServiceOperationResult::IOError.into();
                }
            };

            authorizations.add_authorization(username, hash);

            if let Err(err) = lck.write_auth_file(&authorizations).await {
                eprintln!("❌ Error writing the mount authorizations file: {err}");
                return ServiceOperationResult::IOError.into();
            }
        }

        println!("✅ New mount authorized to user {username}");

        ServiceOperationResult::Ok.into()
    }

    pub async fn check(&self, username: &str, hash: String) -> bool {
        println!("🔑 Requested check for authorization of mount for user {username}");

        // Defeat brute-force searches in an attempt to find an hash collision
        sleep(Duration::from_secs(1)).await;

        let authorizations = match self.auth_mount_op.read().await.read_auth_file().await {
            Ok(auth_str) => auth_str,
            Err(err) => {
                eprintln!("❌ Error opening mount authorizations file: {err}");
                return false;
            }
        };

        authorizations.authorized(username, hash)
    }
}
