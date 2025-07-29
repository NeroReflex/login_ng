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

use std::{
    collections::HashMap,
    ffi::OsString,
    path::{Path, PathBuf},
};

use crate::{
    auth::{SecondaryAuth, SecondaryAuthMethod, SecondaryPassword},
    command::SessionCommand,
    mount::{MountParams, MountPoints},
    user::{MainPassword, UserAuthData},
};

use bytevec2::errors;
use errors::ByteVecError;
use thiserror::Error;
use users::{get_user_by_name, os::unix::UserExt};

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Uhandled data version")]
    UnhandledVersion,

    #[error("Username not recognised")]
    UserDiscoveryError,

    #[error("Home directory not found")]
    HomeDirNotFound(OsString),

    #[error("Error with xattrs: {0}")]
    XAttrError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] ByteVecError),

    #[error("Deserialization error")]
    DeserializationError,
}

/// Represents a source of user authentication data
pub enum StorageSource {
    /// Load/Store operations will be performed on the autodetected home directory
    Username(String),

    /// Load/Store operations will be performed on the given path
    Path(PathBuf),
}

use bytevec2::*;

bytevec_decl! {
    #[derive(PartialEq, Eq, Debug, Copy, Clone)]
    struct AuthDataManifest {
        version: u32
    }
}

impl AuthDataManifest {
    fn new() -> Self {
        Self { version: 0 }
    }
}

bytevec_decl! {
    #[derive(PartialEq, Eq, Debug, Clone)]
    struct MountPointSerialized {
        fstype: String,
        device: String,
        directory: String,
        args: Vec<String>
    }
}

impl From<(&String, &MountParams)> for MountPointSerialized {
    fn from(mount_param: (&String, &MountParams)) -> Self {
        Self {
            directory: mount_param.0.clone(),
            fstype: mount_param.1.fstype().clone(),
            device: mount_param.1.device().clone(),
            args: mount_param.1.flags().clone(),
        }
    }
}

impl From<&MountPointSerialized> for (String, MountParams) {
    fn from(serialized: &MountPointSerialized) -> Self {
        (
            serialized.directory.clone(),
            MountParams::new(
                serialized.device.clone(),
                serialized.fstype.clone(),
                serialized.args.clone(),
            ),
        )
    }
}

bytevec_decl! {
    #[derive(PartialEq, Eq, Debug, Clone)]
    struct SessionCommandSerialized {
        command: String
    }
}

impl From<&SessionCommand> for SessionCommandSerialized {
    fn from(value: &SessionCommand) -> Self {
        let command = value.command();

        Self { command }
    }
}

impl From<SessionCommandSerialized> for SessionCommand {
    fn from(val: SessionCommandSerialized) -> Self {
        SessionCommand::new(val.command.clone())
    }
}

bytevec_decl! {
    #[derive(PartialEq, Eq, Debug, Clone)]
    struct AuthDataSerialized {
        name: String,
        creation_date: u64,
        auth_type: u32,
        auth_data: Vec<u8>
    }
}

impl TryFrom<&SecondaryAuth> for AuthDataSerialized {
    type Error = StorageError;

    fn try_from(value: &SecondaryAuth) -> Result<Self, Self::Error> {
        let name = value.name();
        let creation_date = value.creation_date();

        let (auth_type, auth_data) = match value.data() {
            SecondaryAuthMethod::Password(secondary_password) => (
                0,
                secondary_password
                    .encode::<u16>()
                    .map_err(Self::Error::SerializationError)?,
            ),
        };

        Ok(Self {
            name,
            creation_date,
            auth_data,
            auth_type,
        })
    }
}

impl TryInto<SecondaryAuth> for AuthDataSerialized {
    type Error = StorageError;

    fn try_into(self) -> Result<SecondaryAuth, Self::Error> {
        match self.auth_type {
            0 => Ok(SecondaryAuth::new_password(
                self.name.as_str(),
                Some(self.creation_date),
                SecondaryPassword::decode::<u16>(self.auth_data.as_slice())
                    .map_err(StorageError::SerializationError)?,
            )),
            _ => Err(StorageError::DeserializationError),
        }
    }
}

fn homedir_by_username(username: &String) -> Result<OsString, StorageError> {
    let user = get_user_by_name(&username).ok_or(StorageError::UserDiscoveryError)?;

    let systemd_homed_str: OsString = format!("/home/{username}.homedir").into();
    let systemd_homed_path = Path::new(systemd_homed_str.as_os_str());

    let home_dir_path = match systemd_homed_path.exists() {
        true => systemd_homed_str,
        false => user.home_dir().as_os_str().into(),
    };

    match Path::new(home_dir_path.as_os_str()).exists() {
        true => Ok(home_dir_path),
        false => Err(StorageError::HomeDirNotFound(home_dir_path)),
    }
}

pub fn load_user_session_command(
    source: &StorageSource,
) -> Result<Option<SessionCommand>, StorageError> {
    let home_dir_path = match source {
        StorageSource::Username(username) => homedir_by_username(username)?,
        StorageSource::Path(pathbuf) => pathbuf.as_os_str().to_os_string(),
    };

    let manifest = xattr::get_deref(
        home_dir_path.as_os_str(),
        format!("{}.manifest", crate::DEFAULT_XATTR_NAME),
    )
    .map_err(StorageError::XAttrError)?;
    if manifest.is_none() {
        return Ok(None);
    }

    match xattr::get_deref(
        home_dir_path.as_os_str(),
        format!("{}.session", crate::DEFAULT_XATTR_NAME),
    )
    .map_err(StorageError::XAttrError)?
    {
        Some(bytes) => Ok(Some(
            SessionCommandSerialized::decode::<u32>(bytes.as_slice())
                .map_err(|_| StorageError::DeserializationError)?
                .into(),
        )),
        None => Ok(None),
    }
}

pub fn store_user_session_command(
    settings: &SessionCommand,
    source: &StorageSource,
) -> Result<(), StorageError> {
    let home_dir_path = match source {
        StorageSource::Username(username) => homedir_by_username(username)?,
        StorageSource::Path(pathbuf) => pathbuf.as_os_str().to_os_string(),
    };

    // this is used in case a future format will be required
    let manifest = AuthDataManifest::new();
    let manifest_serialization = manifest
        .encode::<u16>()
        .map_err(StorageError::SerializationError)?;

    // once everything is serialized perform the writing
    xattr::set(
        home_dir_path.as_os_str(),
        format!("{}.manifest", crate::DEFAULT_XATTR_NAME),
        manifest_serialization.as_slice(),
    )
    .map_err(StorageError::XAttrError)?;

    let session_data = SessionCommandSerialized::from(settings);
    let session_serialization = session_data
        .encode::<u32>()
        .map_err(StorageError::SerializationError)?;

    // once everything is serialized perform the writing
    xattr::set(
        home_dir_path.as_os_str(),
        format!("{}.session", crate::DEFAULT_XATTR_NAME),
        session_serialization.as_slice(),
    )
    .map_err(StorageError::XAttrError)?;

    Ok(())
}

pub fn load_user_auth_data(source: &StorageSource) -> Result<Option<UserAuthData>, StorageError> {
    let home_dir_path = match source {
        StorageSource::Username(username) => homedir_by_username(username)?,
        StorageSource::Path(pathbuf) => pathbuf.as_os_str().to_os_string(),
    };

    let manifest = xattr::get_deref(
        home_dir_path.as_os_str(),
        format!("{}.manifest", crate::DEFAULT_XATTR_NAME),
    )
    .map_err(StorageError::XAttrError)?;
    if manifest.is_none() {
        return Ok(None);
    }

    let main = xattr::get_deref(
        home_dir_path.as_os_str(),
        format!("{}.main", crate::DEFAULT_XATTR_NAME),
    )
    .map_err(StorageError::XAttrError)?;
    if main.is_none() {
        return Ok(None);
    }

    let mut auth_data = UserAuthData::new();

    match main {
        Some(a) => {
            let main = MainPassword::decode::<u16>(a.as_slice())
                .map_err(StorageError::SerializationError)?;
            auth_data.push_main(main);
        }
        None => return Ok(None),
    };

    let xattrs = xattr::list_deref(home_dir_path.as_os_str()).map_err(StorageError::XAttrError)?;
    for attr in xattrs.into_iter() {
        if let Some(s) = attr.to_str() {
            if s.starts_with(format!("{}.auth.", crate::DEFAULT_XATTR_NAME).as_str()) {
                let raw_data = xattr::get_deref(home_dir_path.as_os_str(), s)
                    .map_err(StorageError::XAttrError)?
                    .unwrap();
                let serialized_data = AuthDataSerialized::decode::<u32>(raw_data.as_slice())?;

                let secondary_auth: SecondaryAuth = serialized_data.try_into()?;

                auth_data.push_secondary(secondary_auth);
            }
        }
    }

    Ok(Some(auth_data))
}

pub fn remove_user_data(source: &StorageSource) -> Result<(), StorageError> {
    let home_dir_path = match source {
        StorageSource::Username(username) => homedir_by_username(username)?,
        StorageSource::Path(pathbuf) => pathbuf.as_os_str().to_os_string(),
    };

    let xattrs = xattr::list_deref(home_dir_path.as_os_str()).map_err(StorageError::XAttrError)?;
    for attr in xattrs.into_iter() {
        if attr
            .to_string_lossy()
            .starts_with(crate::DEFAULT_XATTR_NAME)
        {
            xattr::remove_deref(home_dir_path.as_os_str(), attr.as_os_str())
                .map_err(StorageError::XAttrError)?
        }
    }

    Ok(())
}

pub fn store_user_auth_data(
    auth_data: UserAuthData,
    source: &StorageSource,
) -> Result<(), StorageError> {
    let home_dir_path = match source {
        StorageSource::Username(username) => homedir_by_username(username)?,
        StorageSource::Path(pathbuf) => pathbuf.as_os_str().to_os_string(),
    };

    // this is used in case a future format will be required
    let manifest = AuthDataManifest::new();
    let manifest_serialization = manifest
        .encode::<u16>()
        .map_err(StorageError::SerializationError)?;

    let maybe_main_password_serialization = match auth_data.main_password() {
        Some(m) => Some(
            m.encode::<u16>()
                .map_err(StorageError::SerializationError)?,
        ),
        None => None,
    };

    // remove everything that was already present
    let xattrs = xattr::list_deref(home_dir_path.as_os_str()).map_err(StorageError::XAttrError)?;
    for attr in xattrs.into_iter() {
        let current_xattr = attr.to_string_lossy();

        if current_xattr.starts_with(format!("{}.auth", crate::DEFAULT_XATTR_NAME).as_str())
            || current_xattr.starts_with(format!("{}.main", crate::DEFAULT_XATTR_NAME).as_str())
        {
            xattr::remove_deref(home_dir_path.as_os_str(), attr.as_os_str())
                .map_err(StorageError::XAttrError)?
        }
    }

    // once everything is serialized perform the writing
    xattr::set(
        home_dir_path.as_os_str(),
        format!("{}.manifest", crate::DEFAULT_XATTR_NAME),
        manifest_serialization.as_slice(),
    )
    .map_err(StorageError::XAttrError)?;

    if let Some(data) = &maybe_main_password_serialization {
        // save the main password first so that if something bad happens after one or more secondary auth may be usable
        xattr::set(
            home_dir_path.as_os_str(),
            format!("{}.main", crate::DEFAULT_XATTR_NAME),
            data.as_slice(),
        )
        .map_err(StorageError::XAttrError)?;

        for (index, val) in auth_data.secondary().enumerate() {
            let serialized_data: AuthDataSerialized = val.try_into()?;
            let raw_data = serialized_data
                .encode::<u32>()
                .map_err(StorageError::SerializationError)?;

            xattr::set(
                home_dir_path.as_os_str(),
                format!("{}.auth.{}", crate::DEFAULT_XATTR_NAME, index),
                raw_data.as_slice(),
            )
            .map_err(StorageError::XAttrError)?
        }
    };
    Ok(())
}

pub fn load_user_mountpoints(source: &StorageSource) -> Result<Option<MountPoints>, StorageError> {
    let home_dir_path = match source {
        StorageSource::Username(username) => homedir_by_username(username)?,
        StorageSource::Path(pathbuf) => pathbuf.as_os_str().to_os_string(),
    };

    let manifest = xattr::get_deref(
        home_dir_path.as_os_str(),
        format!("{}.manifest", crate::DEFAULT_XATTR_NAME),
    )
    .map_err(StorageError::XAttrError)?;
    if manifest.is_none() {
        return Ok(None);
    }

    let main = xattr::get_deref(
        home_dir_path.as_os_str(),
        format!("{}.mount", crate::DEFAULT_XATTR_NAME),
    )
    .map_err(StorageError::XAttrError)?;
    if main.is_none() {
        return Ok(None);
    }

    let mount_data: (String, MountParams) = match main {
        Some(a) => <(String, MountParams)>::from(
            &MountPointSerialized::decode::<u16>(a.as_slice())
                .map_err(StorageError::SerializationError)?,
        ),
        None => return Ok(None),
    };

    let mut mounts = HashMap::new();

    let xattrs = xattr::list_deref(home_dir_path.as_os_str()).map_err(StorageError::XAttrError)?;
    for attr in xattrs.into_iter() {
        if let Some(s) = attr.to_str() {
            if s.starts_with(format!("{}.mounts.", crate::DEFAULT_XATTR_NAME).as_str()) {
                let raw_data = xattr::get_deref(home_dir_path.as_os_str(), s)
                    .map_err(StorageError::XAttrError)?
                    .unwrap();

                let secondary_auth = <(String, MountParams)>::from(
                    &MountPointSerialized::decode::<u32>(raw_data.as_slice())?,
                );

                mounts.insert(secondary_auth.0, secondary_auth.1);
            }
        }
    }

    Ok(Some(MountPoints::new(mount_data.1, mounts)))
}

pub fn store_user_mountpoints(
    mountpoints_data: Option<MountPoints>,
    source: &StorageSource,
) -> Result<(), StorageError> {
    let home_dir_path = match source {
        StorageSource::Username(username) => homedir_by_username(username)?,
        StorageSource::Path(pathbuf) => pathbuf.as_os_str().to_os_string(),
    };

    // this is used in case a future format will be required
    let manifest = AuthDataManifest::new();
    let manifest_serialization = manifest
        .encode::<u16>()
        .map_err(StorageError::SerializationError)?;

    // remove everything that was already present
    let xattrs = xattr::list_deref(home_dir_path.as_os_str()).map_err(StorageError::XAttrError)?;
    for attr in xattrs.into_iter() {
        let current_xattr = attr.to_string_lossy();

        if current_xattr.starts_with(format!("{}.mount", crate::DEFAULT_XATTR_NAME).as_str())
            || current_xattr.starts_with(format!("{}.mounts.", crate::DEFAULT_XATTR_NAME).as_str())
        {
            xattr::remove_deref(home_dir_path.as_os_str(), attr.as_os_str())
                .map_err(StorageError::XAttrError)?
        }
    }

    xattr::set(
        home_dir_path.as_os_str(),
        format!("{}.manifest", crate::DEFAULT_XATTR_NAME),
        manifest_serialization.as_slice(),
    )
    .map_err(StorageError::XAttrError)?;

    let Some(mountpoints) = mountpoints_data else {
        return Ok(());
    };

    let serialized_main_mount: MountPointSerialized =
        MountPointSerialized::from((&String::new(), &mountpoints.mount()));

    let main_mount = serialized_main_mount
        .encode::<u16>()
        .map_err(StorageError::SerializationError)?;

    for (index, val) in mountpoints
        .foreach(|a, b| (a.clone(), b.clone()))
        .iter()
        .enumerate()
    {
        let serialized_data = MountPointSerialized::from((&val.0, &val.1));
        let raw_data = serialized_data
            .encode::<u32>()
            .map_err(StorageError::SerializationError)?;

        xattr::set(
            home_dir_path.as_os_str(),
            format!("{}.mounts.{}", crate::DEFAULT_XATTR_NAME, index),
            raw_data.as_slice(),
        )
        .map_err(StorageError::XAttrError)?
    }

    // save the home mount last so that if something bad happens an invalid mount won't be attempted
    xattr::set(
        home_dir_path.as_os_str(),
        format!("{}.mount", crate::DEFAULT_XATTR_NAME),
        main_mount.as_slice(),
    )
    .map_err(StorageError::XAttrError)?;

    Ok(())
}
