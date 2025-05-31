use crate::execve_wrapper_cstr;
use crate::{execve_wrapper, find_program_path, runner::Runner, cstr::CStr};
use std::ffi::{OsStr};
use std::io::{BufReader, Read};
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

pub fn mktemp_dir<S, Q>(path: S, dir: Q) -> String
where
    S: AsRef<OsStr>,
    Q: AsRef<OsStr>,
{
    // Call the mktemp command
    let output = Command::new("mktemp")
        .arg("-p")
        .arg(path)
        .arg("-d")
        .arg("-t")
        .arg(dir)
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
        return
    }

    // Handle the error
    let error_message = std::str::from_utf8(&output.stderr).expect("Invalid UTF-8 error output");
    panic!("Error in mkfifo: {}", error_message)
}

pub struct GamescopeExecveRunner {
    gamescope_cmd: String,
    gamescope_args: Vec<String>,
    shared_env: Vec<(String, String)>,
    socket: PathBuf,
    stats: PathBuf,
}

impl GamescopeExecveRunner {
    pub fn new(splitted: Vec<String>) -> Self {
        let xdg_runtime_dir = PathBuf::from(match std::env::var("XDG_RUNTIME_DIR") {
            Ok(env) => env,
            Err(err) => {
                eprint!("Error in fetching XDG_RUNTIME_DIR: {err}");

                String::from("/tmp/")
            }
        });

        let tmp_dir = PathBuf::from(mktemp_dir(&xdg_runtime_dir, "gamescope.XXXXXXX"));
        let socket = tmp_dir.join("startup.socket");
        let stats = tmp_dir.join("stats.pipe");

        mkfifo(&socket);
        mkfifo(&stats);

        let mangohud_configfile = mktemp(xdg_runtime_dir.join("mangohud.XXXXXXXX"));
        std::fs::write(PathBuf::from(&mangohud_configfile), b"no_display").unwrap();

        let radv_force_vrs_config_filec = mktemp(xdg_runtime_dir.join("radv_vrs.XXXXXXXX"));
        std::fs::write(PathBuf::from(&radv_force_vrs_config_filec), b"1x1").unwrap();

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
                gamescope_args.push(String::from("-R"));
                gamescope_args.push(String::from(
                    socket.as_os_str().to_string_lossy().to_string().as_str(),
                ));
                gamescope_args.push(String::from("-T"));
                gamescope_args.push(String::from(
                    stats.as_os_str().to_string_lossy().to_string().as_str(),
                ));
            } else {
                gamescope_args.push(argument);
            }
        }

        // These are copied from gamescope-session-plus
        let shared_env = vec![
            (
                String::from("GAMESCOPE_STATS"),
                String::from(stats.to_string_lossy()),
            ),
            (
                String::from("RADV_FORCE_VRS_CONFIG_FILE"),
                radv_force_vrs_config_filec,
            ),
            (String::from("MANGOHUD_CONFIGFILE"), mangohud_configfile),
            // Force Qt applications to run under xwayland
            (String::from("QT_QPA_PLATFORM"), String::from("xcb")),
            // Expose vram info from radv
            (String::from("WINEDLLOVERRIDES"), String::from("dxgi=n")),
            (
                String::from("SDL_VIDEO_MINIMIZE_ON_FOCUS_LOSS"),
                String::from("0"),
            ),
            // Temporary crutch until dummy plane interactions / etc are figured out
            //(String::from("GAMESCOPE_DISABLE_ASYNC_FLIPS"), String::from("1")),
        ];

        Self {
            gamescope_cmd,
            gamescope_args,
            shared_env,
            socket,
            stats,
        }
    }

    fn start_mangoapp(&self) -> Result<(), Box<dyn std::error::Error>> {
        // gamescope won't start unless we read data from the socket:
        let file = std::fs::File::open(&self.socket).unwrap();
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

        let mut mangoapp_envp_data: Vec<CStr> = vec![];
        let mut mangoapp_argv_data: Vec<CStr> = vec![];
        let mangoapp_prog = match find_program_path("mangoapp") {
            Ok(program_path) => CStr::new(program_path.as_str()).unwrap(),
            Err(err) => {
                println!("Error searching for the specified program: {err}");
                CStr::new("mangoapp").unwrap()
            }
        };

        mangoapp_argv_data.push(CStr::new(mangoapp_prog.as_str()).unwrap());

        for (key, value) in std::env::vars() {
            let c_string = CStr::new(format!("{key}={value}").as_str()).unwrap();
            mangoapp_envp_data.push(c_string);
        }

        for (key, val) in self.shared_env.iter() {
            let c_string = CStr::new(format!("{key}={val}").as_str()).unwrap();
            mangoapp_envp_data.push(c_string);
        }

        mangoapp_envp_data.push(CStr::new(format!("DISPLAY={response_x_display}").as_str()).unwrap());
        mangoapp_envp_data.push(
            CStr::new(format!("GAMESCOPE_WAYLAND_DISPLAY={response_wl_display}").as_str()).unwrap(),
        );

        execve_wrapper_cstr(&mangoapp_prog, &mangoapp_argv_data, &mangoapp_envp_data)
    }

    fn start_gamescope(&self) -> Result<(), Box<dyn std::error::Error>> {
        let gamescope_prog = CStr::new(self.gamescope_cmd.as_str()).unwrap();
        let gamescope_argv_data = self
            .gamescope_args
            .iter()
            .map(|argv| CStr::new(argv.as_str()).unwrap())
            .collect::<Vec<_>>();
        let gamescope_envp_data: Vec<CStr> = std::env::vars()
            .map(|(key, value)| CStr::new(format!("{key}={value}").as_str()).unwrap())
            .chain(
                self.shared_env
                    .iter()
                    .map(|(key, val)| CStr::new(format!("{key}={val}").as_str()).unwrap()),
            )
            .collect::<Vec<_>>();

        execve_wrapper_cstr(&gamescope_prog, &gamescope_argv_data, &gamescope_envp_data)
    }
}

impl Runner for GamescopeExecveRunner {
    fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut mangoapp_cmd = Command::new("mangoapp");
        for (key, val) in self.shared_env.iter() {
            mangoapp_cmd.env(key, val);
        }

        let fork_res = unsafe { libc::fork() };
        if fork_res < 0 {
            panic!("Could not fork the process");
        } else if fork_res == 0 {
            self.start_mangoapp()
        } else {
            self.start_gamescope()
        }
    }
}
