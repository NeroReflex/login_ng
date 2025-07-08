use std::fs::{self, create_dir, File};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use crate::pam::ServiceError;

pub async fn create_directory(dirpath: PathBuf) -> Result<(), ServiceError> {
    let dir_path_str = dirpath.as_os_str().to_string_lossy();

    if !dirpath.as_path().exists() {
        match create_dir(dirpath.as_path()) {
            Ok(_) => {
                println!("📁 Directory {dir_path_str} created");

                let mut permissions = fs::metadata(dirpath.as_path())?.permissions();
                permissions.set_mode(0o700);

                fs::set_permissions(dirpath.as_path(), permissions)?;
            }
            Err(err) => {
                eprintln!("❌ Could not create directory {dir_path_str}: {err}");

                return Err(ServiceError::IOError(err));
            }
        }
    }

    Ok(())
}

pub async fn read_file_or_create_default<F>(
    filepath: PathBuf,
    default: F,
) -> Result<String, ServiceError>
where
    F: FnOnce() -> Result<String, ServiceError>,
{
    let file_path = filepath.as_path();
    let file_path_dbg = file_path.as_os_str().to_string_lossy();

    let contents = match file_path.exists() {
        true => {
            let mut contents = String::new();

            let mut file = File::open(file_path)?;
            let read = file.read_to_string(&mut contents)?;
            println!("📖 Read private key file of {read} bytes");

            contents
        }
        false => {
            eprintln!("🖊️ File {file_path_dbg} not found: a new one will be generated...",);

            let contents = default()?;

            match File::create(file_path) {
                Ok(mut file) => {
                    let metadata = file.metadata()?;
                    let mut perm = metadata.permissions();
                    perm.set_mode(0o700);

                    fs::set_permissions(file_path, perm)?;
                    match file.write_all(contents.to_string().as_bytes()) {
                        Ok(_) => {
                            println!("✅ Generated key has been saved to {file_path_dbg}")
                        }
                        Err(err) => {
                            eprintln!(
                                "❌ Failed to write the generated key to {file_path_dbg}: {err}"
                            );

                            return Err(ServiceError::IOError(err));
                        }
                    };
                }
                Err(err) => {
                    eprintln!("❌ Failed to create the file {file_path_dbg}: {err}");

                    return Err(ServiceError::IOError(err));
                }
            };

            contents
        }
    };

    Ok(contents)
}
