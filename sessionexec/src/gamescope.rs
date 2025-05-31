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
}

impl GamescopeExecveRunner {
    pub fn new(
        splitted: Vec<String>,
        mangohud: bool,
        stats: bool,
        env: Vec<(String, String)>,
    ) -> Self {
       
        Self {
        }
    }

    fn start_gamescope(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut cmd = Command::new("gamescope");
        cmd.args(vec![
            String::from("-e"),
            String::from("--steam"),
            String::from("--"),
            String::from("steam"),
            String::from("-steampal"),
            String::from("-steamdeck"),
            String::from("-gamepadui"),
        ].iter());
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
