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

#[cfg(feature = "pam")]
use std::{
    ffi::{CStr, CString},
    sync::{Arc, Mutex},
};

use crate::interactions::{prompt_password, prompt_plain};
#[cfg(feature = "pam")]
use pam::{error::ErrorCode, conversation::ConversationHandler};

use crate::interactions::{conversation::*, login::LoginUserInteractionHandler};

use crate::{
    storage::{load_user_auth_data, StorageSource},
    user::UserAuthData,
};

pub struct TrivialCommandLineConversationPrompter {
    plain: Option<String>,
    hidden: Option<String>,
}

impl TrivialCommandLineConversationPrompter {
    pub fn new(plain: Option<String>, hidden: Option<String>) -> Self {
        Self { plain, hidden }
    }
}

impl ConversationPrompter for TrivialCommandLineConversationPrompter {
    fn echo_on_prompt(&mut self, _prompt: &String) -> Option<String> {
        self.plain.clone()
    }

    fn echo_off_prompt(&mut self, _prompt: &String) -> Option<String> {
        self.hidden.clone()
    }

    fn display_info(&mut self, prompt: &String) {
        println!("{}", prompt)
    }

    fn display_error(&mut self, prompt: &String) {
        eprintln!("{}", prompt)
    }
}

#[cfg(feature = "pam")]
pub struct CommandLineConversation {
    answerer: Option<Arc<Mutex<dyn ConversationPrompter>>>,
    recorder: Option<Arc<Mutex<dyn ConversationRecorder>>>,
}

#[cfg(feature = "pam")]
impl CommandLineConversation {
    /// Creates a new null conversation handler
    #[must_use]
    pub fn new(
        answerer: Option<Arc<Mutex<dyn ConversationPrompter>>>,
        recorder: Option<Arc<Mutex<dyn ConversationRecorder>>>,
    ) -> Self {
        Self { answerer, recorder }
    }

    pub fn attach_recorder(&mut self, recorder: Arc<Mutex<dyn ConversationRecorder>>) {
        self.recorder = Some(recorder)
    }
}

#[cfg(feature = "pam")]
impl Default for CommandLineConversation {
    fn default() -> Self {
        Self::new(None, None)
    }
}

#[cfg(feature = "pam")]
impl ConversationHandler for CommandLineConversation {
    fn prompt_echo_on(&mut self, msg: &CStr) -> Result<CString, ErrorCode> {
        let prompt = format!("{}", msg.to_string_lossy());

        let response: String = match self.answerer {
            Some(ref ans) => match ans.lock() {
                Ok(mut guard) => match guard.echo_on_prompt(&prompt) {
                    Some(answer) => answer,
                    None => prompt_plain(prompt.as_str()).map_err(|_err| ErrorCode::CONV_ERR)?,
                },
                Err(_) => prompt_plain(prompt.as_str()).map_err(|_err| ErrorCode::CONV_ERR)?,
            },
            None => prompt_plain(prompt.as_str()).map_err(|_err| ErrorCode::CONV_ERR)?,
        };

        if let Some(recorder) = &self.recorder {
            if let Ok(mut guard) = recorder.lock() {
                guard.record_echo_on(prompt, response.clone());
            }
        }

        Ok(CString::new(response).map_err(|_err| ErrorCode::CONV_ERR)?)
    }

    fn prompt_echo_off(&mut self, msg: &CStr) -> Result<CString, ErrorCode> {
        let prompt = format!("{}", msg.to_string_lossy());

        let response: String = match self.answerer {
            Some(ref ans) => match ans.lock() {
                Ok(mut guard) => match guard.echo_off_prompt(&prompt) {
                    Some(answer) => answer,
                    None => prompt_password(prompt.as_str()).map_err(|_err| ErrorCode::CONV_ERR)?,
                },
                Err(_) => prompt_password(prompt.as_str()).map_err(|_err| ErrorCode::CONV_ERR)?,
            },
            None => prompt_password(prompt.as_str()).map_err(|_err| ErrorCode::CONV_ERR)?,
        };

        if let Some(recorder) = &self.recorder {
            if let Ok(mut guard) = recorder.lock() {
                guard.record_echo_off(prompt, response.clone());
            }
        }

        Ok(CString::new(response).map_err(|_err| ErrorCode::CONV_ERR)?)
    }

    fn text_info(&mut self, msg: &CStr) {
        let string = format!("{}", msg.to_string_lossy());

        match self.answerer {
            Some(ref ans) => match ans.lock() {
                Ok(mut guard) => guard.display_info(&string),
                Err(_) => {}
            },
            None => {}
        };
    }

    fn error_msg(&mut self, msg: &CStr) {
        let string = format!("{}", msg.to_string_lossy());

        match self.answerer {
            Some(ref ans) => match ans.lock() {
                Ok(mut guard) => guard.display_info(&string),
                Err(_) => {}
            },
            None => {}
        };
    }
}

#[derive(Default)]
pub struct CommandLineLoginUserInteractionHandler {
    attempt_autologin: bool,

    maybe_user: Option<UserAuthData>,

    maybe_username: Option<String>,

    maybe_password: Option<String>,
}

impl CommandLineLoginUserInteractionHandler {
    pub fn new(
        attempt_autologin: bool,
        maybe_username: Option<String>,
        maybe_password: Option<String>,
    ) -> Self {
        let maybe_user = match &maybe_username {
            Some(username) => {
                load_user_auth_data(&StorageSource::Username(username.clone())).map_or(None, |a| a)
            }
            None => None,
        };

        Self {
            attempt_autologin,
            maybe_user,
            maybe_username,
            maybe_password,
        }
    }
}

impl LoginUserInteractionHandler for CommandLineLoginUserInteractionHandler {
    fn provide_username(&mut self, username: &String) {
        self.maybe_user =
            load_user_auth_data(&StorageSource::Username(username.clone())).map_or(None, |a| a)
    }

    fn prompt_secret(&mut self, msg: &String) -> Option<String> {
        if self.attempt_autologin {
            if let Some(user_cfg) = &self.maybe_user {
                if let Ok(main_password) = user_cfg.main_by_auth(&Some(String::new())) {
                    return Some(main_password);
                }
            }
        }

        match &self.maybe_password {
            Some(password) => match &self.maybe_user {
                Some(user_cfg) => match user_cfg.main_by_auth(&Some(password.clone())) {
                    Ok(main_password) => Some(main_password),
                    Err(_) => Some(password.clone()),
                },
                None => Some(password.clone()),
            },
            None => match prompt_password(msg.as_str()) {
                Ok(provided_secret) => match &self.maybe_user {
                    Some(user_cfg) => match user_cfg.main_by_auth(&Some(provided_secret.clone())) {
                        Ok(main_password) => Some(main_password),
                        Err(_) => Some(provided_secret),
                    },
                    None => Some(provided_secret),
                },
                Err(_) => None,
            },
        }
    }

    fn prompt_plain(&mut self, msg: &String) -> Option<String> {
        match &self.maybe_username {
            Some(username) => Some(username.clone()),
            None => prompt_plain(msg.as_str()).ok(),
        }
    }

    fn print_info(&mut self, msg: &String) {
        println!("{}", msg)
    }

    fn print_error(&mut self, msg: &String) {
        eprintln!("{}", msg)
    }
}
