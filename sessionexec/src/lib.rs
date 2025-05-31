use std::{error::Error, ffi::CString, process::Command};

use cstr::CStr;

pub(crate) mod cstr;
pub mod execve;
pub mod gamescope;
pub mod plasma;
pub mod runner;

pub(crate) fn find_program_path(program: &str) -> Result<String, Box<dyn Error>> {
    let output = Command::new("which").arg(program).output()?;

    if output.status.success() {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(path)
    } else {
        Err(format!("Program '{}' not found in PATH", program).into())
    }
}

pub(crate) fn execve_wrapper(
    prog: &CString,
    argv_data: &Vec<CString>,
    envp_data: &Vec<CString>,
) -> Result<(), Box<dyn std::error::Error>> {
    let prog = prog.as_ptr();

    let argv = argv_data
        .iter()
        .map(|e| e.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect::<Vec<*const libc::c_char>>();

    let envp = envp_data
        .iter()
        .map(|e| e.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect::<Vec<*const libc::c_char>>();

    let execve_err = unsafe { libc::execve(prog, argv.as_ptr(), envp.as_ptr()) };

    if execve_err == -1 {
        return Err(format!("execve failed: {}", std::io::Error::last_os_error()).into());
    }

    unreachable!()
}

pub(crate) fn execve_wrapper_cstr(
    prog: &CStr,
    argv_data: &Vec<CStr>,
    envp_data: &Vec<CStr>,
) -> Result<(), Box<dyn std::error::Error>> {
    let prog = prog.inner();

    let argv = argv_data
        .iter()
        .map(|e| e.inner())
        .chain(std::iter::once(std::ptr::null()))
        .collect::<Vec<*const libc::c_char>>();

    let envp = envp_data
        .iter()
        .map(|e| e.inner())
        .chain(std::iter::once(std::ptr::null()))
        .collect::<Vec<*const libc::c_char>>();

    let execve_err = unsafe { libc::execve(prog, argv.as_ptr(), envp.as_ptr()) };

    if execve_err == -1 {
        return Err(format!("execve failed: {}", std::io::Error::last_os_error()).into());
    }

    unreachable!()
}
