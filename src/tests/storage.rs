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

#[test]
fn test_main_password_serialization() {
    let first_main = "main password <3".to_string();
    let intermediate = "intermediate_key".to_string();

    let provided_password = Some(first_main.clone());

    let dir_name = "test1";

    let source = crate::storage::StorageSource::Path(std::path::PathBuf::from(dir_name));

    {
        let mut user_cfg = crate::user::UserAuthData::new();

        // set the main password
        user_cfg.set_main(&first_main, &intermediate).unwrap();

        assert_eq!(
            user_cfg.main_by_auth(&provided_password).unwrap(),
            first_main
        );

        std::fs::create_dir(dir_name).unwrap();
        crate::storage::store_user_auth_data(user_cfg, &source).unwrap();
    }

    match crate::storage::load_user_auth_data(&source) {
        Ok(reloaded) => {
            std::fs::remove_dir(dir_name).unwrap();
            assert_eq!(
                reloaded
                    .as_ref()
                    .unwrap()
                    .main_by_auth(&provided_password)
                    .unwrap(),
                first_main
            )
        }
        Err(error) => {
            std::fs::remove_dir(dir_name).unwrap();
            let error_str = format!("{}", error);
            eprintln!("{}", error_str);
            assert_eq!(1, 2)
        }
    }
}

#[test]
fn test_secondary_password_serialization() {
    let correct_main = "main password <3".to_string();
    let intermediate = "intermediate_key".to_string();
    let secondary_passwords = ["daisujda".to_string(), "sfaffsss".to_string()];

    let dir_name = "test2";
    let source = crate::storage::StorageSource::Path(std::path::PathBuf::from(dir_name));

    {
        let mut user_cfg = crate::user::UserAuthData::new();
        user_cfg.set_main(&correct_main, &intermediate).unwrap();

        // register every secondary password in the test vector
        for (idx, sp) in secondary_passwords.iter().enumerate() {
            user_cfg
                .add_secondary_password(format!("test{}", idx).as_str(), &intermediate, sp)
                .unwrap();
        }

        std::fs::create_dir(dir_name).unwrap();
        crate::storage::store_user_auth_data(user_cfg, &source).unwrap();
    }

    let mut tested: usize = 0;
    match crate::storage::load_user_auth_data(&source) {
        Ok(reloaded) => {
            std::fs::remove_dir(dir_name).unwrap();

            // attempt to login with each secondary password

            for sp in secondary_passwords.iter() {
                let secondary_password = Some(sp.clone());
                assert_eq!(
                    reloaded
                        .as_ref()
                        .unwrap()
                        .main_by_auth(&secondary_password)
                        .unwrap(),
                    correct_main
                );
                tested += 1;
            }
        }
        Err(error) => {
            std::fs::remove_dir(dir_name).unwrap();
            let error_str = format!("{}", error);
            eprintln!("{}", error_str);
        }
    }

    assert_eq!(tested, secondary_passwords.len());
}
