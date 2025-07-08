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

use rs_sha512::*;
use std::hash::{BuildHasher, Hasher};

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MountParams {
    fstype: String,
    device: String,
    flags: Vec<String>,
}

impl MountParams {
    pub fn new(device: String, fstype: String, flags: Vec<String>) -> Self {
        Self {
            device,
            fstype,
            flags,
        }
    }

    pub fn device(&self) -> &String {
        &self.device
    }

    pub fn set_device(&mut self, device: String) {
        self.device = device;
    }

    pub fn fstype(&self) -> &String {
        &self.fstype
    }

    pub fn set_fstype(&mut self, fstype: String) {
        self.fstype = fstype;
    }

    pub fn flags(&self) -> &Vec<String> {
        &self.flags
    }

    pub fn set_flags(&mut self, flags: Vec<String>) {
        self.flags = flags;
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MountPoints {
    /// hashmap of directories -> mountdata
    mounts: HashMap<String, MountParams>,

    home: MountParams,
}

impl MountPoints {
    pub fn new(home: MountParams, mounts: HashMap<String, MountParams>) -> Self {
        Self { home, mounts }
    }

    pub fn foreach<F, R>(&self, fun: F) -> Vec<R>
    where
        F: Fn(&String, &MountParams) -> R,
    {
        self.mounts
            .keys()
            .filter_map(|a| self.mounts.get(a).map(|b| fun(a, b)))
            .collect::<Vec<R>>()
    }

    pub fn add_premount(&mut self, dir: &String, mnt: &MountParams) {
        self.mounts.insert(dir.clone(), mnt.clone());
    }

    pub fn with_premount(&self, dir: &String, mnt: &MountParams) -> Self {
        let mut n: MountPoints = self.clone();
        n.mounts.remove(dir);
        n.add_premount(dir, mnt);
        n
    }

    pub fn mount(&self) -> MountParams {
        self.home.clone()
    }

    pub fn with_mount(&self, mnt: &MountParams) -> Self {
        let mut n: MountPoints = self.clone();
        n.set_mount(mnt);
        n
    }

    pub fn set_mount(&mut self, mnt: &MountParams) {
        self.home = mnt.clone();
    }

    pub fn hash(&self) -> String {
        let mut hasher = Sha512State::default().build_hasher();

        hasher.write(self.home.device().as_bytes());
        hasher.write(self.home.fstype().as_bytes());
        hasher.write(self.home.flags.concat().as_bytes());

        for (i, m) in self.mounts.iter().enumerate() {
            hasher.write_usize(i);
            hasher.write_u8(0);
            hasher.write(m.0.as_bytes());
            hasher.write_u8(1);
            hasher.write(m.1.device().as_bytes());
            hasher.write_u8(2);
            hasher.write(m.1.fstype().as_bytes());
            hasher.write_u8(3);
            for (i1, a) in m.1.flags().iter().enumerate() {
                hasher.write_usize(i1);
                hasher.write(a.as_bytes());
            }
        }

        let numeric_hash: u64 = hasher.finish();

        format!("{:X}", numeric_hash)
    }
}
