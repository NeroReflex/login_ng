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

use std::{os::unix::process::CommandExt, path::Path, process::Command};

use crate::pam_binding::context::{Context, Flag};

use thiserror::Error;

use crate::{
    interactions::{conversation::ProxyLoginUserInteractionHandlerConversation, login::*},
    users::{get_user_by_name, os::unix::UserExt},
};

#[derive(Debug, Error)]
pub enum PamLoginError {
    #[error("Error setting login prompt: {0}")]
    SetPrompt(String),

    #[error("Error authenticating the user: {0}")]
    Authentication(String),

    #[error("Error validating the user: ")]
    Validation(String),

    #[error("Error opening session: {0}")]
    Open(String),

    #[error("Error obtaining the user from PAM: {0}")]
    GetUser(String),

    #[error("Error executing command: ")]
    Execution(String),

    #[error("Unable to find the username")]
    UnknownUsername,
}

pub struct PamLoginExecutor {
    conversation: ProxyLoginUserInteractionHandlerConversation,
    allow_autologin: bool,
}

impl PamLoginExecutor {
    pub fn new(
        conversation: ProxyLoginUserInteractionHandlerConversation,
        allow_autologin: bool,
    ) -> Self {
        Self {
            conversation,
            allow_autologin,
        }
    }
}

impl LoginExecutor for PamLoginExecutor {
    fn execute(
        &mut self,
        maybe_username: &Option<String>,
        retrival_strategy: &SessionCommandRetrival,
    ) -> Result<LoginResult, LoginError> {
        let user_prompt = Some("username: ");

        let mut context = Context::new(
            match self.allow_autologin {
                true => "login_ng-autologin",
                false => "login_ng",
            },
            maybe_username.as_ref().map(|a| a.as_str()),
            self.conversation.clone(),
        )
        .expect("Failed to initialize PAM context");

        context
            .set_user_prompt(user_prompt)
            .map_err(|err| LoginError::PamError(PamLoginError::SetPrompt(err.to_string())))?;

        // Authenticate the user (ask for password, 2nd-factor token, fingerprint, etc.)
        context
            .authenticate(Flag::NONE)
            .map_err(|err| LoginError::PamError(PamLoginError::Authentication(err.to_string())))?;

        // Validate the account (is not locked, expired, etc.)
        context
            .acct_mgmt(Flag::NONE)
            .map_err(|err| LoginError::PamError(PamLoginError::Validation(err.to_string())))?;

        // Get resulting user name and map to a user id
        let username = context
            .user()
            .map_err(|err| LoginError::PamError(PamLoginError::GetUser(err.to_string())))?;
        let logged_user = get_user_by_name(&username).ok_or(LoginError::UserDiscoveryError)?;

        // Open session and initialize credentials
        let session = context
            .open_session(Flag::NONE)
            .map_err(|err| LoginError::PamError(PamLoginError::Open(err.to_string())))?;

        // The retrival of default session MUST be done after the account has been unlocked
        let command = retrieve_session_command_for_user(&username, &retrival_strategy);

        // Run a process in the PAM environment
        let _result = Command::new(command.command())
            .env_clear()
            .envs(session.envlist().iter())
            .uid(logged_user.uid())
            .gid(logged_user.primary_group_id())
            /*
            // unstable feature
            .groups(
                logged_user
                    .groups()
                    .unwrap_or(vec![])
                    .iter()
                    .filter(|g| g.gid() != logged_user.primary_group_id())
                    .map(|g| g.gid())
                    .collect::<Vec<u32>>()
                    .as_slice(),
            )
            */
            .current_dir(match logged_user.home_dir().exists() {
                true => logged_user.home_dir(),
                false => Path::new("/"),
            })
            .status()
            .map_err(|err| LoginError::PamError(PamLoginError::Execution(err.to_string())))?;

        Ok(LoginResult::Success)
    }
}
