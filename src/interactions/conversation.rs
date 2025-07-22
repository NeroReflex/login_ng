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
use crate::interactions::login::LoginUserInteractionHandler;

#[cfg(feature = "pam")]
use pam::{conversation::ConversationHandler, error::PamErrorCode};

#[cfg(feature = "pam")]
use std::{
    ffi::{CStr, CString},
    sync::{Arc, Mutex},
};

#[derive(Debug, Clone)]
pub enum ConversationInteraction {
    EchoOn { prompt: String, response: String },
    EchoOff { prompt: String, response: String },
}

pub trait ConversationRecorder {
    fn record_echo_on(&mut self, prompt: String, response: String);

    fn record_echo_off(&mut self, prompt: String, response: String);

    fn recorded_username(&self, user_prompt: &Option<&str>) -> Option<String>;

    fn recorded_password(&self) -> Option<String>;
}

#[derive(Default)]
pub struct SimpleConversationRecorder {
    recording: Vec<ConversationInteraction>,
}

impl SimpleConversationRecorder {
    #[must_use]
    pub fn new() -> Self {
        Self { recording: vec![] }
    }
}

impl ConversationRecorder for SimpleConversationRecorder {
    fn record_echo_on(&mut self, prompt: String, response: String) {
        self.recording
            .push(ConversationInteraction::EchoOn { prompt, response });
    }

    fn record_echo_off(&mut self, prompt: String, response: String) {
        self.recording
            .push(ConversationInteraction::EchoOff { prompt, response });
    }

    fn recorded_username(&self, user_prompt: &Option<&str>) -> Option<String> {
        for r in self.recording.iter().rev() {
            if let ConversationInteraction::EchoOn { prompt, response } = r {
                match user_prompt {
                    Some(expected_prompt) => {
                        if expected_prompt == prompt {
                            return Some(response.clone());
                        }
                    }
                    None => {
                        if prompt.contains("login:") {
                            return Some(response.clone());
                        }
                    }
                }
            }
        }

        None
    }

    fn recorded_password(&self) -> Option<String> {
        for r in self.recording.iter().rev() {
            if let ConversationInteraction::EchoOff {
                prompt: _,
                response,
            } = r
            {
                return Some(response.clone());
            }
        }

        None
    }
}

pub trait ConversationPrompter {
    fn echo_on_prompt(&mut self, prompt: &String) -> Option<String>;

    fn echo_off_prompt(&mut self, prompt: &String) -> Option<String>;

    fn display_info(&mut self, prompt: &String);

    fn display_error(&mut self, prompt: &String);
}

#[cfg(feature = "pam")]
#[derive(Clone)]
pub struct ProxyLoginUserInteractionHandlerConversation {
    inner: Arc<Mutex<dyn LoginUserInteractionHandler>>,
}

#[cfg(feature = "pam")]
impl ProxyLoginUserInteractionHandlerConversation {
    pub fn new(inner: Arc<Mutex<dyn LoginUserInteractionHandler>>) -> Self {
        Self { inner }
    }
}

#[cfg(feature = "pam")]
impl ConversationHandler for ProxyLoginUserInteractionHandlerConversation {
    fn prompt_echo_on(&mut self, msg: &CStr) -> Result<CString, PamErrorCode> {
        let msg = format!("{}", msg.to_string_lossy());

        let mut guard = self.inner.lock().map_err(|_| PamErrorCode::CONV_ERR)?;
        match guard.prompt_plain(&msg) {
            Some(response) => Ok(CString::new(response).map_err(|_err| PamErrorCode::CONV_ERR)?),
            None => Err(PamErrorCode::CONV_ERR),
        }
    }

    fn prompt_echo_off(&mut self, msg: &CStr) -> Result<CString, PamErrorCode> {
        let msg = format!("{}", msg.to_string_lossy());

        let mut guard = self.inner.lock().map_err(|_| PamErrorCode::CONV_ERR)?;
        match guard.prompt_secret(&msg) {
            Some(response) => Ok(CString::new(response).map_err(|_err| PamErrorCode::CONV_ERR)?),
            None => Err(PamErrorCode::CONV_ERR),
        }
    }

    fn text_info(&mut self, msg: &CStr) {
        let msg = format!("{}", msg.to_string_lossy());

        match self.inner.lock().map_err(|_| PamErrorCode::CONV_ERR) {
            Ok(mut guard) => guard.print_info(&msg),
            Err(err) => eprintln!(
                "had to info about '{}', but an error occurred: {:?}",
                msg, err
            ),
        }
    }

    fn error_msg(&mut self, msg: &CStr) {
        let msg = format!("{}", msg.to_string_lossy());

        match self.inner.lock().map_err(|_| PamErrorCode::CONV_ERR) {
            Ok(mut guard) => guard.print_error(&msg),
            Err(err) => eprintln!(
                "had to info about '{}', but an error occurred: {:?}",
                msg, err
            ),
        }
    }
}
