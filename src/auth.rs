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

use std::time::{SystemTime, UNIX_EPOCH};

use bytevec2::*;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};

extern crate bcrypt;
use bcrypt::{hash, verify, DEFAULT_COST};

use crate::{
    error::*,
    user::{AuthDataNonce, AuthDataSalt, UserAuthDataError},
};

bytevec_decl! {
    #[derive(Debug, Eq, PartialEq, Clone)]
    pub struct SecondaryPassword {
        enc_intermediate_nonce: AuthDataNonce,
        enc_intermediate: Vec<u8>, // this is encrypted with the (password, enc_intermediate_nonce)

        password_salt: AuthDataSalt,

        password_hash: String // this is used to check the entered password
    }
}

impl SecondaryPassword {
    // WARNING: it is the user responsibility to check that the intermediate value matches the MainPassword field,
    // therefore the user MUST verify() it beforehand
    pub fn new(intermediate: &String, password: &String) -> Result<Self, UserOperationError> {
        let password_salt_arr =
            <[u8; 32]>::try_from(Aes256Gcm::generate_key(&mut OsRng).to_vec().as_slice()).unwrap();

        let password_hash =
            hash(password.as_str(), DEFAULT_COST).map_err(UserOperationError::HashingError)?;

        let password_derived_key = crate::derive_key(password.as_str(), &password_salt_arr);

        let key = Key::<Aes256Gcm>::from_slice(&password_derived_key);

        let cipher = Aes256Gcm::new(key);

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let enc_intermediate = cipher
            .encrypt(&nonce, crate::password_to_vec(intermediate).as_ref())
            .map_err(UserOperationError::EncryptionError)?;

        let temp: [u8; 32] = password_salt_arr;
        let password_salt = AuthDataSalt::from(temp);
        let temp: [u8; 12] = nonce.into();
        let enc_intermediate_nonce = AuthDataNonce::from(temp);
        Ok(Self {
            enc_intermediate_nonce,
            enc_intermediate,
            password_salt,
            password_hash,
        })
    }

    // get the intermediate if the password is correct
    pub fn intermediate(&self, password: &String) -> Result<String, UserOperationError> {
        if !verify(password.as_str(), self.password_hash.as_str())
            .map_err(UserOperationError::HashingError)?
        {
            return Err(UserOperationError::User(
                UserAuthDataError::CouldNotAuthenticate,
            ));
        }

        let temp: [u8; 32] = self.password_salt.into();
        let password_derived_key = crate::derive_key(password.as_str(), temp.as_slice());

        let key = Key::<Aes256Gcm>::from_slice(&password_derived_key);
        let cipher = Aes256Gcm::new(key);

        let temp: [u8; 12] = self.enc_intermediate_nonce.into();
        let nonce = Nonce::from_slice(temp.as_slice());

        let dec_result = cipher
            .decrypt(nonce, self.enc_intermediate.as_ref())
            .map_err(UserOperationError::EncryptionError)?;

        Ok(crate::vec_to_password(&dec_result))
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct SecondaryAuth {
    name: String,
    creation_date: u64,
    method: SecondaryAuthMethod,
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum SecondaryAuthMethod {
    Password(SecondaryPassword),
}

impl SecondaryAuth {
    pub fn new_password(
        name: &str,
        creation_date: Option<u64>,
        password: SecondaryPassword,
    ) -> Self {
        Self {
            name: String::from(name),
            creation_date: match creation_date {
                Some(date) => date,
                None => match SystemTime::now().duration_since(UNIX_EPOCH) {
                    Ok(from_epoch) => from_epoch.as_secs(),
                    Err(_err) => 0u64,
                },
            },
            method: SecondaryAuthMethod::Password(password),
        }
    }

    pub(crate) fn data(&self) -> &SecondaryAuthMethod {
        &self.method
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn creation_date(&self) -> u64 {
        self.creation_date
    }

    pub fn type_name(&self) -> String {
        match self.method {
            SecondaryAuthMethod::Password(_) => String::from("password"),
        }
    }

    pub fn intermediate(
        &self,
        secondary_password: &Option<String>,
    ) -> Result<String, UserOperationError> {
        match &self.method {
            SecondaryAuthMethod::Password(pwd) => match &secondary_password {
                Some(provided_secondary) => pwd.intermediate(provided_secondary),
                None => Err(UserOperationError::User(
                    UserAuthDataError::MatchingAuthNotProvided,
                )),
            },
        }
    }
}
