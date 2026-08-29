use juno::{
    LifecycleCommand, LifecycleOptions, RecoveryStrategy, Roots, VerifyRequest, execute_lifecycle,
    verifier_login, verify,
};
use std::ffi::OsString;

fn main() {
    match run(std::env::args_os().skip(1).collect()) {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("juno: {error}");
            std::process::exit(2);
        }
    }
}

fn run(arguments: Vec<OsString>) -> Result<String, Box<dyn std::error::Error>> {
    let Some(command) = arguments.first().and_then(|value| value.to_str()) else {
        return Err(usage().into());
    };
    if matches!(command, "version" | "--version" | "-V") {
        if arguments.len() != 1 {
            return Err(usage().into());
        }
        return Ok(format!("juno {}", juno::VERSION));
    }
    if command == "verifier" {
        if arguments.len() != 2 || arguments[1] != "login" {
            return Err("usage: juno verifier login".into());
        }
        return verifier_login(&Roots::from_environment()?).map_err(Into::into);
    }
    if command == "verify" {
        let mut repo = None;
        let mut packet = None;
        let mut json = false;
        let mut index = 1;
        while index < arguments.len() {
            match arguments[index]
                .to_str()
                .ok_or("arguments must be valid UTF-8")?
            {
                "--repo" => {
                    index += 1;
                    repo = Some(
                        arguments
                            .get(index)
                            .ok_or("--repo needs a path")?
                            .clone()
                            .into(),
                    );
                }
                "--packet" => {
                    index += 1;
                    packet = Some(
                        arguments
                            .get(index)
                            .ok_or("--packet needs a path")?
                            .clone()
                            .into(),
                    );
                }
                "--json" => json = true,
                argument => return Err(format!("unknown verify argument: {argument}").into()),
            }
            index += 1;
        }
        let request = VerifyRequest {
            repo: repo.ok_or("verify needs --repo PATH")?,
            packet: packet.ok_or("verify needs --packet FILE")?,
            json,
        };
        return verify(&request, &Roots::from_environment()?).map_err(Into::into);
    }

    let mut options = LifecycleOptions::default();
    let mut strategy = None;
    let mut index = 1;
    while index < arguments.len() {
        let argument = arguments[index]
            .to_str()
            .ok_or("arguments must be valid UTF-8")?;
        match argument {
            "--apply" => {
                index += 1;
                options.apply = Some(
                    arguments
                        .get(index)
                        .and_then(|value| value.to_str())
                        .ok_or("--apply needs a plan ID")?
                        .to_string(),
                );
            }
            "--allow-shared-files" => options.allow_shared_files = true,
            "--allow-conflict-overwrite" => options.allow_conflict_overwrite = true,
            "--json" => options.json = true,
            "--strategy" => {
                index += 1;
                strategy = Some(
                    match arguments.get(index).and_then(|value| value.to_str()) {
                        Some("complete") => RecoveryStrategy::Complete,
                        Some("rollback") => RecoveryStrategy::Rollback,
                        _ => return Err("--strategy must be complete or rollback".into()),
                    },
                );
            }
            "--yes" => return Err("--yes is not supported".into()),
            _ => return Err(format!("unknown argument: {argument}").into()),
        }
        index += 1;
    }

    let command = match command {
        "install" | "update" | "uninstall" => {
            if strategy.is_some() || options.json || options.allow_conflict_overwrite {
                return Err(format!("unsupported option for {command}").into());
            }
            match command {
                "install" => LifecycleCommand::Install,
                "update" => LifecycleCommand::Update,
                _ => LifecycleCommand::Uninstall,
            }
        }
        "doctor" => {
            if options.apply.is_some()
                || options.allow_shared_files
                || options.allow_conflict_overwrite
                || strategy.is_some()
            {
                return Err("doctor accepts only --json".into());
            }
            LifecycleCommand::Doctor
        }
        "recover" => {
            if options.json {
                return Err("recover does not accept --json".into());
            }
            LifecycleCommand::Recover {
                strategy: strategy.ok_or("recover needs --strategy complete or rollback")?,
            }
        }
        _ => return Err(usage().into()),
    };
    let roots = Roots::from_environment()?;
    execute_lifecycle(command, &options, &roots).map_err(Into::into)
}

fn usage() -> &'static str {
    "usage: juno install|update|uninstall|doctor|recover|verify|verifier|version"
}
