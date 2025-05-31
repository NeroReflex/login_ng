
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    use sessionexec::execve::ExecveRunner;
    use sessionexec::gamescope::GamescopeExecveRunner;
    use sessionexec::plasma::PlasmaRunner;
    use sessionexec::runner::Runner;
    use std::path::PathBuf;
/*
    use ini::Ini;
    

    let args: Vec<String> = std::env::args().collect();

    let param = if args.len() < 2 {
        match std::env::home_dir() {
            Some(home_dir) => {
                let path = home_dir.join(".config").join("sessionexec").join("default");
                if path.exists() && path.is_file() {
                    match std::fs::read_to_string(path) {
                        Ok(session) => session.trim().to_string(),
                        Err(err) => {
                            println!("error reading file ~/.config/sessionexec/default: {err}");
                            String::from("game-mode.desktop")
                        }
                    }
                } else {
                    println!(
                        "file ~/.config/sessionexec/default not found: using game-mode.desktop"
                    );
                    String::from("game-mode.desktop")
                }
            }
            None => String::from("game-mode.desktop"),
        }
    } else {
        args[1].to_string()
    };

    let path = match std::fs::exists(&param)? {
        false => PathBuf::from("/usr/share/wayland-sessions/").join(param),
        true => PathBuf::from(&param),
    };

    let splitted = match std::fs::exists(&path)? {
        true => {
            let conf = Ini::load_from_file(path)?;

            let section = conf.section(Some("Desktop Entry")).unwrap();
            let exec = section.get("Exec").unwrap();

            exec.split_whitespace()
                .map(|a| a.to_string())
                .collect::<Vec<String>>()
        }
        false => vec![String::from("startplasma-wayland")],
    };

    if splitted.is_empty() {
        panic!("No command specified!");
    }
*/

    let splitted = vec![
        String::from("gamescope"),
        String::from("-e"),
        String::from("--steam"),
        String::from("--"),
        String::from("steam"),
        String::from("-steampal"),
        String::from("-steamdeck"),
        String::from("-gamepadui"),
    ];


    let mut executor: Box<dyn Runner> = Box::new(GamescopeExecveRunner::new(
            vec![],
            false,
            false,
            vec![],
        ));

    executor.run()
}
