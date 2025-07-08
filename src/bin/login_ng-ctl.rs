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

use std::fmt::Debug;
use std::path::PathBuf;

use chrono::Local;
use chrono::TimeZone;
use login_ng::command::SessionCommand;
use login_ng::mount::MountParams;
use login_ng::storage::load_user_mountpoints;
use login_ng::storage::load_user_session_command;
use login_ng::storage::store_user_mountpoints;
use login_ng::storage::store_user_session_command;
use login_ng::storage::StorageSource;
use login_ng::storage::{load_user_auth_data, remove_user_data, store_user_auth_data};
use login_ng::user::UserAuthData;

use login_ng::interactions::prompt_password;

#[cfg(feature = "pam")]
use pam::context::{Context, Flag};

use argh::FromArgs;

#[derive(FromArgs, PartialEq, Debug)]
/// Command line tool for managing login-ng authentication methods
struct Args {
    #[cfg(feature = "pam")]
    #[argh(option, short = 'u')]
    /// username to be used, if unspecified it will be autodetected: if that fails it will be prompted for
    username: Option<String>,

    #[argh(option, short = 'd')]
    /// force the use of a specific home directory
    directory: Option<PathBuf>,

    #[argh(option, short = 'p')]
    /// main password for authentication (the one accepted by PAM)
    password: Option<String>,

    #[argh(switch)]
    /// force update of the user configuration if required
    update_as_needed: Option<bool>,

    #[argh(subcommand)]
    command: Command,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
/// Subcommands for managing authentication methods
enum Command {
    Info(InfoCommand),
    Setup(SetupCommand),
    Reset(ResetCommand),
    Inspect(InspectCommand),
    Add(AddAuthCommand),
    SetSession(SetSessionCommand),
    ChangeMainMount(ChangeMainMountCommand),
    ChangeSecondaryMount(ChangeSecondaryMountCommand),
}

#[derive(FromArgs, PartialEq, Debug)]
/// Print information about the software
#[argh(subcommand, name = "info")]
struct InfoCommand {}

#[derive(FromArgs, PartialEq, Debug)]
/// Set the mount command that has to be used to mount the user home directory
#[argh(subcommand, name = "set-pre-mount")]
struct ChangeSecondaryMountCommand {
    #[argh(option)]
    /// directory to mount the device into
    dir: String,

    #[argh(option)]
    /// device to mount
    device: String,

    #[argh(option)]
    /// filesystem type (corresponds to -t flag in mount)
    fstype: String,

    #[argh(option)]
    /// mount options relative to the filesystem type (corresponds to -o flag in mount)
    flags: Vec<String>,
}

#[derive(FromArgs, PartialEq, Debug)]
/// Set the mount command that has to be used to mount the user home directory
#[argh(subcommand, name = "set-home-mount")]
struct ChangeMainMountCommand {
    #[argh(option)]
    /// device to mount
    device: String,

    #[argh(option)]
    /// filesystem type (corresponds to -t flag in mount)
    fstype: String,

    #[argh(option)]
    /// mount options relative to the filesystem type (corresponds to -o flag in mount)
    flags: Vec<String>,
}

#[derive(FromArgs, PartialEq, Debug)]
/// Setup initial authentication data also creating a new intermediate key
#[argh(subcommand, name = "setup")]
struct SetupCommand {
    #[argh(option, short = 'i')]
    /// the intermediate key
    intermediate: Option<String>,
}

#[derive(FromArgs, PartialEq, Debug)]
/// Set the default session command to be executed when a user login if nothing else is being specified
#[argh(subcommand, name = "set-session")]
struct SetSessionCommand {
    #[argh(option)]
    /// command to execute
    cmd: String,

    #[argh(option)]
    /// additional arguments for the command
    args: Vec<String>,
}

#[derive(FromArgs, PartialEq, Debug)]
/// Reset additional authentication data also destroying the intermediate key
#[argh(subcommand, name = "reset")]
struct ResetCommand {}

#[derive(FromArgs, PartialEq, Debug)]
/// Inspects user login settings
#[argh(subcommand, name = "inspect")]
struct InspectCommand {}

#[derive(FromArgs, PartialEq, Debug)]
/// Add a new authentication method
#[argh(subcommand, name = "add")]
struct AddAuthCommand {
    #[argh(option)]
    /// name of the authentication method
    name: String,

    #[argh(option)]
    /// intermediate key (the key used to unlock the main password)
    intermediate: Option<String>,

    #[argh(subcommand)]
    method: AddAuthMethod,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
/// Subcommands for adding an authentication method
enum AddAuthMethod {
    Password(AddAuthPasswordCommand),
}

#[derive(FromArgs, PartialEq, Debug)]
/// Command to add a new authentication method
#[argh(subcommand, name = "password")]
struct AddAuthPasswordCommand {
    #[argh(option)]
    /// secondary password for authentication
    secondary_pw: Option<String>,
}

fn main() {
    let args: Args = argh::from_env();

    #[cfg(not(feature = "pam"))]
    let (storage_source, maybe_main_password) = match args.directory {
        Some(path) => (StorageSource::Path(path), args.password),
        None => panic!("This software has been compiled without pam support: you must specify the home directory of the target user"),
    };

    #[cfg(feature = "pam")]
    let (storage_source, maybe_main_password) = match (args.username, args.directory) {
        (args_username, None) => {
            use std::sync::Arc;
            use std::sync::Mutex;

            use login_ng::interactions::cli::*;
            use login_ng::interactions::conversation::*;

            let user_prompt = Some("username: ");

            let answerer = Arc::new(Mutex::new(TrivialCommandLineConversationPrompter::new(
                args_username.clone(),
                args.password.clone(),
            )));

            let interaction_recorder = Arc::new(Mutex::new(SimpleConversationRecorder::new()));

            let username = match args_username {
                Some(username) => Some(username),
                None => match login_ng::users::get_current_username() {
                    Some(username) => match username.to_str() {
                        Some(u) => match u {
                            "root" => None,
                            username => Some(String::from(username)),
                        },
                        None => None,
                    },
                    None => None,
                },
            };

            let mut context = Context::new(
                "login_ng-ctl", // this cannot be changed as setting the main password won't be possible (or it will be unverified)
                username.as_deref(),
                CommandLineConversation::new(Some(answerer), Some(interaction_recorder.clone())),
            )
            .expect("Failed to initialize PAM context");

            context.set_user_prompt(user_prompt).unwrap();

            // Authenticate the user (ask for password, 2nd-factor token, fingerprint, etc.)
            context
                .authenticate(Flag::NONE)
                .expect("Authentication failed");

            // Validate the account (is not locked, expired, etc.)
            context
                .acct_mgmt(Flag::NONE)
                .expect("Account validation failed");

            let username = username.clone().unwrap_or_else(|| {
                interaction_recorder
                    .lock()
                    .unwrap()
                    .recorded_username(&user_prompt)
                    .unwrap()
            });

            let main_password = match interaction_recorder.lock().unwrap().recorded_password() {
                Some(main_password) => Some(main_password),
                None => args.password,
            };

            (StorageSource::Username(username.clone()), main_password)
        }
        (_, Some(path)) => (StorageSource::Path(path), args.password),
    };

    let mut user_cfg = match load_user_auth_data(&storage_source) {
        Ok(load_res) => match load_res {
            Some(auth_data) => auth_data,
            None => UserAuthData::new(),
        },
        Err(err) => {
            eprintln!("There is a problem loading your configuration file: {err}.\nAborting.");
            std::process::exit(-1)
        }
    };

    let mut user_mounts = match load_user_mountpoints(&storage_source) {
        Ok(existing_data) => existing_data,
        Err(err) => {
            eprintln!("Error in loading user mounts data: {err}");
            std::process::exit(-1)
        }
    };

    let mut write_file = args.update_as_needed;
    match args.command {
        Command::Info(_) => {
            let version = login_ng::LIBRARY_VERSION;
            println!("login-ng version {version}, Copyright (C) 2024 Denis Benato");
            println!("login-ng comes with ABSOLUTELY NO WARRANTY;");
            println!("This is free software, and you are welcome to redistribute it");
            println!("under certain conditions.");
            println!("\n");
        }
        Command::ChangeSecondaryMount(mount_data) => {
            let Some(new_data) = user_mounts else {
                eprintln!("Error in changing user mounts: a main mount has not beed defined");
                std::process::exit(-1)
            };

            user_mounts = Some(new_data.with_premount(
                &mount_data.dir,
                &MountParams::new(mount_data.device, mount_data.fstype, mount_data.flags),
            ));

            write_file = Some(true)
        }
        Command::ChangeMainMount(mount_data) => {
            user_mounts = Some(
                user_mounts
                    .unwrap_or_default()
                    .with_mount(&MountParams::new(
                        mount_data.device,
                        mount_data.fstype,
                        mount_data.flags,
                    )),
            );

            write_file = Some(true)
        }
        Command::SetSession(session_data) => {
            let command = SessionCommand::new(session_data.cmd);

            match store_user_session_command(&command, &storage_source) {
                Ok(_) => {}
                Err(err) => {
                    eprintln!("Error in changing the user default session: {err}");
                    std::process::exit(-1)
                }
            }
        }
        Command::Setup(s) => {
            if user_cfg.has_main() {
                eprintln!("User already has an intermediate key present: use reset if you want to delete the old one");
                std::process::exit(-1)
            }

            let intermediate_key = match s.intermediate {
                Some(ik) => ik.clone(),
                None => {
                    let ik = prompt_password("intermediate key:").unwrap();
                    let ikc = prompt_password("intermediate key (confirm):").unwrap();

                    if ik != ikc {
                        eprintln!("Intermediate key and confirmation not matching");
                        std::process::exit(-1)
                    }

                    ik
                }
            };

            let password = match &maybe_main_password {
                Some(password) => password.clone(),
                None => prompt_password("main password:").unwrap(),
            };

            user_cfg = UserAuthData::new();
            match user_cfg.set_main(&password, &intermediate_key) {
                Ok(_) => {
                    // Force the write of the populated User structure
                    write_file = Some(true);
                }
                Err(err) => {
                    eprintln!("Error in initializing the user authentication data: {err}");
                    std::process::exit(-1)
                }
            };
        }
        Command::Reset(_) => {
            match remove_user_data(&storage_source) {
                Ok(_) => {
                    // Do NOT rewrite the User structure that was created while authenticating the user
                    write_file = Some(false)
                }
                Err(err) => {
                    eprintln!("Error in resetting user additional athentication methods: {err}");
                    std::process::exit(-1)
                }
            }
        }
        Command::Inspect(_) => {
            match &storage_source {
                StorageSource::Username(username) => {
                    println!("-----------------------------------------------------------");
                    println!("User: {username}");
                    println!("-----------------------------------------------------------");
                }
                StorageSource::Path(path) => {
                    println!("-----------------------------------------------------------");
                    println!("Path: {}", path.to_string_lossy());
                    println!("-----------------------------------------------------------");
                }
            }

            match user_mounts {
                Some(ref mount_info) => {
                    let hash = mount_info.hash();
                    println!("hash: {hash}");

                    let primary_mount = mount_info.mount();
                    println!("device: {}", primary_mount.device());
                    if !primary_mount.fstype().is_empty() {
                        println!("filesystem: {}", primary_mount.fstype());
                    }

                    println!("args: {}", primary_mount.flags().join(","));

                    mount_info.foreach(|a, b| {
                        println!("***********************************************************");
                        println!("    directory: {}", a.clone());
                        println!("    device: {}", b.device().clone());
                        println!("    filesystem: {}", b.fstype().clone());
                        println!("    args: {}", b.flags().join(","))
                    });
                }
                None => println!("No user-defined mounts"),
            }

            println!("-----------------------------------------------------------");

            match load_user_session_command(&storage_source) {
                Ok(maybe_data) => match maybe_data {
                    Some(data) => {
                        let cmd = data.command();
                        println!("Default session command: {cmd}")
                    }
                    None => println!("No default session set."),
                },
                Err(err) => {
                    eprintln!("Error in reading the user default session: {}", err);
                    std::process::exit(-1)
                }
            };

            println!("-----------------------------------------------------------");

            let methods_count = user_cfg.secondary().len();
            match methods_count {
                0 => {
                    println!("No authentication methods configured.");
                }
                1 => {
                    println!("There is 1 authentication method: ");
                    println!("-----------------------------------------------------------");
                }
                _ => {
                    println!(
                        "There are {} authentication methods: ",
                        user_cfg.secondary().len()
                    );
                    println!("-----------------------------------------------------------");
                }
            }

            for s in user_cfg.secondary() {
                println!("name: {}", s.name());
                println!(
                    "    created at: {:?}",
                    Local
                        .timestamp_opt(s.creation_date() as i64, 0)
                        .unwrap()
                        .to_string()
                );
                println!("    type: {}", s.type_name());
                println!("-----------------------------------------------------------");
            }
        }
        Command::Add(add_cmd) => {
            let intermediate_password = match user_cfg.has_main() {
                false => add_cmd.intermediate.clone().unwrap_or_else(|| {
                    let intermediate_password = prompt_password("Intermediate key:")
                        .expect("Failed to read intermediate key");

                    let intermediate_password_repeat =
                        prompt_password("Intermediate key (repeat):")
                            .expect("Failed to read intermediate key (repeat)");

                    if intermediate_password != intermediate_password_repeat {
                        eprintln!("Intermediate key and and Intermediate (repeat) do not match!");

                        std::process::exit(-1)
                    }

                    intermediate_password
                }),
                true => add_cmd.intermediate.clone().unwrap_or_else(|| {
                    prompt_password("Intermediate key:").expect("Failed to read intermediate key")
                }),
            };

            if user_cfg.has_main() {
                if let Err(err) = user_cfg.main_by_auth(&Some(intermediate_password.clone())) {
                    eprintln!(
                        "Could not verify the correctness of the intermediate key: {}",
                        err
                    );
                    std::process::exit(-1)
                }
            }

            // if the main password is accepted update the stored one
            if let Some(main_password) = maybe_main_password {
                user_cfg
                    .set_main(&main_password, &intermediate_password)
                    .expect("Error handling main password");
            }

            match add_cmd.method {
                AddAuthMethod::Password(add_auth_password_command) => {
                    let secondary_password = match add_auth_password_command.secondary_pw {
                        Some(secondary_password) => secondary_password,
                        None => {
                            let secondary_password = prompt_password("Secondary password:")
                                .expect("Failed to read secondary password");

                            let repeat = prompt_password("Secondary password (repeat):")
                                .expect("Failed to read secondary password (repeat)");
                            if secondary_password != repeat {
                                eprintln!("Passwords do not match.\nAborting.");
                                std::process::exit(-1)
                            }

                            secondary_password
                        }
                    };

                    if !user_cfg.has_main() {
                        eprintln!("Cannot add a secondary password for an account with no main password.\nAborting.");
                        std::process::exit(-1);
                    }

                    match user_cfg.add_secondary_password(
                        &add_cmd.name,
                        &intermediate_password,
                        &secondary_password,
                    ) {
                        Ok(_) => {
                            write_file = Some(true);
                            println!("Secondary password added.");
                        }
                        Err(err) => {
                            eprintln!("Error adding a secondary password: {}.\nAborting.", err);
                            std::process::exit(-1);
                        }
                    }
                }
            }
        }
    }

    if write_file.unwrap_or_default() {
        store_user_auth_data(user_cfg, &storage_source)
            .expect("Error saving the updated user auth data.\nAborting.");

        store_user_mountpoints(user_mounts, &storage_source)
            .expect("Error saving the updated user mount data.\nAborting.");
    }
}
