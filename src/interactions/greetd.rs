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

use crate::interactions::{login::LoginUserInteractionHandler, login::*};

use std::{
    os::unix::net::UnixStream,
    sync::{Arc, Mutex},
};

use greetd_ipc::{codec::SyncCodec, AuthMessageType, ErrorType, Request, Response};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum GreetdLoginError {
    #[error("Error connecting to greetd: {0}")]
    GreetdConnectionError(#[from] std::io::Error),

    #[error("Error in greetd connection: {0}")]
    GreetdIpcError(#[from] greetd_ipc::codec::Error),

    #[error("Unknown error in greetd: {0}")]
    GreetdUnknownError(String),

    #[error("No username provided")]
    NoUsernameProvided,

    #[error("Mutex error")]
    MutexError,
}

pub struct GreetdLoginExecutor {
    greetd_sock: String,

    prompter: Arc<Mutex<dyn LoginUserInteractionHandler>>,
}

impl GreetdLoginExecutor {
    pub fn new(greetd_sock: String, prompter: Arc<Mutex<dyn LoginUserInteractionHandler>>) -> Self {
        Self {
            greetd_sock,
            prompter,
        }
    }
}

impl LoginExecutor for GreetdLoginExecutor {
    fn execute(
        &mut self,
        maybe_username: &Option<String>,
        retrival_strategy: &SessionCommandRetrival,
    ) -> Result<LoginResult, LoginError> {
        let mut stream = UnixStream::connect(&self.greetd_sock)
            .map_err(|err| LoginError::GreetdError(GreetdLoginError::GreetdConnectionError(err)))?;

        let mutexed_prompter = self.prompter.clone();

        let mut prompter = mutexed_prompter
            .lock()
            .map_err(|_| LoginError::GreetdError(GreetdLoginError::MutexError))?;

        let username =
            match maybe_username {
                Some(username) => username.clone(),
                None => prompter.prompt_plain(&String::from("login: ")).ok_or(
                    LoginError::GreetdError(GreetdLoginError::NoUsernameProvided),
                )?,
            };

        prompter.provide_username(&username);

        let mut next_request = Request::CreateSession {
            username: username.clone(),
        };
        let mut starting = false;
        loop {
            next_request
                .write_to(&mut stream)
                .map_err(|err| LoginError::GreetdError(GreetdLoginError::GreetdIpcError(err)))?;

            match Response::read_from(&mut stream)
                .map_err(|err| LoginError::GreetdError(GreetdLoginError::GreetdIpcError(err)))?
            {
                Response::AuthMessage {
                    auth_message,
                    auth_message_type,
                } => {
                    let response = match auth_message_type {
                        AuthMessageType::Visible => prompter.prompt_plain(&auth_message),
                        AuthMessageType::Secret => prompter.prompt_secret(&auth_message),
                        AuthMessageType::Info => {
                            eprintln!("info: {auth_message}");
                            None
                        }
                        AuthMessageType::Error => {
                            eprintln!("error: {auth_message}");
                            None
                        }
                    };

                    next_request = Request::PostAuthMessageResponse { response };
                }
                Response::Success => {
                    if starting {
                        return Ok(LoginResult::Success);
                    } else {
                        starting = true;

                        // The retrival of default session MUST be done after the account has been unlocked
                        let command =
                            retrieve_session_command_for_user(&username, retrival_strategy);

                        next_request = Request::StartSession {
                            env: vec![],
                            cmd: vec![command.command()], // TODO: arguments?
                        }
                    }
                }
                Response::Error {
                    error_type,
                    description,
                } => {
                    Request::CancelSession
                        .write_to(&mut stream)
                        .map_err(|err| {
                            LoginError::GreetdError(GreetdLoginError::GreetdIpcError(err))
                        })?;
                    match error_type {
                        ErrorType::AuthError => return Ok(LoginResult::Failure),
                        ErrorType::Error => {
                            return Err(LoginError::GreetdError(
                                GreetdLoginError::GreetdUnknownError(description),
                            ))
                        }
                    }
                }
            }
        }
    }
}
