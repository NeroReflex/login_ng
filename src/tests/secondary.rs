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
fn test_autologin() {
    let correct_main = "main password <3".to_string();
    let intermediate = "intermediate_key".to_string();
    let autologin = String::new();

    let mut user_cfg = crate::user::UserAuthData::new();
    user_cfg.set_main(&correct_main, &intermediate).unwrap();
    user_cfg
        .add_secondary_password("prova", &intermediate, &autologin)
        .unwrap();

    let secondary_password = Some(autologin);
    assert_eq!(
        user_cfg.main_by_auth(&secondary_password).unwrap(),
        correct_main
    );
}

#[test]
fn test_secondary() {
    let correct_main = "main password <3".to_string();
    let intermediate = "intermediate_key".to_string();
    let secondary_passwords = ["daisujda".to_string(), "sfaffsss".to_string()];

    let mut user_cfg = crate::user::UserAuthData::new();
    user_cfg.set_main(&correct_main, &intermediate).unwrap();

    // register every secondary password in the test vector
    for (idx, sp) in secondary_passwords.iter().enumerate() {
        user_cfg
            .add_secondary_password(format!("test{}", idx).as_str(), &intermediate, sp)
            .unwrap();
    }

    // attempt to login with each secondary password
    let mut tested: usize = 0;
    for sp in secondary_passwords.iter() {
        let secondary_password = Some(sp.clone());
        assert_eq!(
            user_cfg.main_by_auth(&secondary_password).unwrap(),
            correct_main
        );
        tested += 1;
    }

    assert_eq!(tested, secondary_passwords.len());
}
