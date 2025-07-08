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

pub mod cli;
pub mod conversation;
pub mod login;

#[cfg(feature = "pam")]
pub mod pam;

#[cfg(feature = "greetd")]
pub mod greetd;

pub use rpassword::prompt_password;

pub const DEFAULT_CMD: &str = "/bin/sh";

/// Reads a password from the TTY
fn read_plain(stream: std::fs::File) -> std::io::Result<String> {
    use std::io::BufRead;

    let mut reader = std::io::BufReader::new(stream);

    let mut answer = String::new();
    reader.read_line(&mut answer)?;

    fix_line_issues(answer)
}

/// Normalizes the return of `read_line()` in the context of a CLI application
fn fix_line_issues(mut line: String) -> std::io::Result<String> {
    if !line.ends_with('\n') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "unexpected end of file",
        ));
    }

    // Remove the \n from the line.
    line.pop();

    // Remove \r and \n from the line if present
    if (line.ends_with('\r')) || (line.ends_with('\n')) {
        line.pop();
    }

    // Ctrl-U should remove the line in terminals
    if line.contains('') {
        line = match line.rfind('') {
            Some(last_ctrl_u_index) => line[last_ctrl_u_index + 1..].to_string(),
            None => line,
        };
    }

    Ok(line)
}

pub fn prompt_plain(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    use std::io::Write;

    let mut stream = std::fs::OpenOptions::new()
        .write(true)
        .read(true)
        .open("/dev/tty")?;

    Ok(stream
        .write_all(prompt.to_string().as_bytes())
        .and_then(|_| stream.flush())
        .and_then(|_| read_plain(stream))
        .map_err(Box::new)?)
}
