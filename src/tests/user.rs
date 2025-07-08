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
fn test_main_password_change() {
    let first_main = "main password <3".to_string();
    let second_main = "2nd main password :B".to_string();
    let intermediate = "intermediate_key".to_string();

    let mut user_cfg = crate::user::UserAuthData::new();

    // set the main password
    user_cfg.set_main(&first_main, &intermediate).unwrap();

    // change the main password
    user_cfg.set_main(&second_main, &intermediate).unwrap();
}

#[test]
fn test_main_password_auth() {
    let first_main = "main password <3".to_string();
    let intermediate = "intermediate_key".to_string();

    let mut user_cfg = crate::user::UserAuthData::new();

    // set the main password
    user_cfg.set_main(&first_main, &intermediate).unwrap();

    let provided_password = Some(first_main.clone());
    assert_eq!(
        user_cfg.main_by_auth(&provided_password).unwrap(),
        first_main
    );
}
