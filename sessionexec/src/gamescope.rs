use crate::{find_program_path, runner::Runner};
use std::ffi::OsStr;
use std::io::{BufReader, Read};
use std::thread::spawn;
use std::{path::PathBuf, process::Command};

pub fn mktemp<S>(n: S) -> String
where
    S: AsRef<OsStr>,
{
    // Call the mktemp command
    let output = Command::new("mktemp")
        .arg(n)
        .output()
        .expect("Failed to execute mktemp");

    // Check if the command was successful
    if output.status.success() {
        // Convert the output to a string
        let temp_file_path = std::str::from_utf8(&output.stdout).expect("Invalid UTF-8 output");

        // Print the path of the temporary file
        String::from(temp_file_path.trim())
    } else {
        // Handle the error
        let error_message =
            std::str::from_utf8(&output.stderr).expect("Invalid UTF-8 error output");
        panic!("Error: {}", error_message)
    }
}

pub fn mkfifo<S>(n: S)
where
    S: AsRef<OsStr>,
{
    // Call the mktemp command
    let output = Command::new("mkfifo")
        .arg("--")
        .arg(n)
        .output()
        .expect("Failed to execute mktemp");

    // Check if the command was successful
    if output.status.success() {
        return;
    }

    // Handle the error
    let error_message = std::str::from_utf8(&output.stderr).expect("Invalid UTF-8 error output");
    panic!("Error in mkfifo: {}", error_message)
}

#[derive(Clone, Debug)]
pub struct GamescopeExecveRunner {
    gamescope_cmd: String,
    gamescope_args: Vec<String>,
    environment: Vec<(String, String)>,
    socket: Option<PathBuf>,
}

impl GamescopeExecveRunner {
    pub fn new(
        splitted: Vec<String>,
        mangohud: bool,
        stats: bool,
        env: Vec<(String, String)>,
    ) -> Self {
        let xdg_runtime_dir = PathBuf::from(match std::env::var("XDG_RUNTIME_DIR") {
            Ok(env) => env,
            Err(err) => {
                eprint!("Error in fetching XDG_RUNTIME_DIR: {err}");

                String::from("/tmp/")
            }
        });

        let socket = match mangohud {
            true => {
                let socket = xdg_runtime_dir.join("startup.socket");
                mkfifo(&socket);
                Some(socket)
            }
            false => None,
        };

        let stats = match stats {
            true => {
                let stats = xdg_runtime_dir.join("stats.pipe");
                mkfifo(&stats);
                Some(stats.to_string_lossy().to_string())
            }
            false => None,
        };

        //let radv_vrs = mktemp(xdg_runtime_dir.join("radv_vrs.XXXXXXXX"));
        //std::fs::write(PathBuf::from(&radv_vrs), b"1x1").unwrap();

        let mut gamescope_cmd = String::new();
        let mut gamescope_args = vec![];
        for (idx, val) in splitted.iter().enumerate() {
            let argument = String::from(val.as_str());
            if idx == 0 {
                gamescope_cmd = match find_program_path(val.as_str()) {
                    Ok(program_path) => String::from(program_path.as_str()),
                    Err(err) => {
                        println!("Error searching for the specified program: {err}");
                        gamescope_cmd.clone()
                    }
                };

                gamescope_args.push(argument);
                match &socket {
                    Some(s) => {
                        gamescope_args.push(String::from("-R"));
                        gamescope_args.push(String::from(s.to_string_lossy().to_string().as_str()));
                    }
                    None => {}
                }
                match &stats {
                    Some(stats) => {
                        gamescope_args.push(String::from("-T"));
                        gamescope_args.push(String::from(stats.as_str()));
                    }
                    None => {}
                };
            } else {
                gamescope_args.push(argument);
            }
        }

        /*
        let shared_env = [
            //("RADV_FORCE_VRS_CONFIG_FILE", radv_vrs.as_str()),
            // Force Qt applications to run under xwayland
            ("QT_QPA_PLATFORM", "xcb"),
            // Expose vram info from radv
            ("WINEDLLOVERRIDES", "dxgi=n"),
            ("SDL_VIDEO_MINIMIZE_ON_FOCUS_LOSS", "0"),
            // Temporary crutch until dummy plane interactions / etc are figured out
            //(String::from("GAMESCOPE_DISABLE_ASYNC_FLIPS"), String::from("1")),
        ];

        // These are copied from gamescope-session-plus
        let mut environment = shared_env
            .iter()
            .map(|(a, b)| (String::from(*a), String::from(*b)))
            .collect::<Vec<_>>();
        */

        let mut environment = vec![];
        match &stats {
            Some(stats) => environment.push((String::from("GAMESCOPE_STATS"), stats.clone())),
            None => {}
        };

        if mangohud {
            let mangohud_configfile = mktemp(xdg_runtime_dir.join("mangohud.XXXXXXXX"));
            std::fs::write(PathBuf::from(&mangohud_configfile), b"no_display").unwrap();

            environment.push((String::from("MANGOHUD_CONFIGFILE"), mangohud_configfile));
        }

        for (key, val) in env.iter() {
            environment.push((key.clone(), val.clone()));
        }

        Self {
            gamescope_cmd,
            gamescope_args,
            environment,
            socket,
        }
    }

    fn start_mangoapp<T>(&self, socket: T) -> Result<(), Box<dyn std::error::Error>>
    where
        T: AsRef<std::path::Path>,
    {
        // gamescope won't start unless we read data from the socket:
        let file = std::fs::File::open(&socket).unwrap();
        let mut reader = BufReader::new(file);

        let mut response = String::new();
        let (response_x_display, response_wl_display) = match reader.read_to_string(&mut response) {
            Ok(read_result) => {
                println!("Read response ({read_result}): {response}");

                let split = response
                    .split_whitespace()
                    .map(String::from)
                    .collect::<Vec<String>>();

                if split.len() != 2 {
                    panic!("Invalid read from socket!");
                }

                (split[0].clone(), split[1].clone())
            }
            Err(err) => {
                panic!("Error reading read_wl_display_result: {err}")
            }
        };

        let mut cmd = Command::new("mangoapp");
        cmd.env_clear();
        cmd.envs(self.environment.clone());
        cmd.env("DISPLAY", response_x_display);
        cmd.env("GAMESCOPE_WAYLAND_DISPLAY", response_wl_display);

        let mut child = cmd.spawn()?;

        child.wait()?;

        Ok(())
    }

    fn start_gamescope(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut cmd = Command::new("gamescope");
        cmd.args(self.gamescope_args.iter());
        /*cmd.env_clear();
        cmd.envs(self.environment.clone());*/

        cmd.spawn()?.wait_with_output()?;

        Ok(())
    }
}

impl Runner for GamescopeExecveRunner {
    fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.start_gamescope().unwrap();

        Ok(())
    }
}
