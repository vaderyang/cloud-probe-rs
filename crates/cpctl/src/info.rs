//! cpworker process info command. Port of `cpctl/cmd/info.go`.

use cpgolib::cpworker::{self, Client};

use crate::cli::Globals;

pub fn run(globals: &Globals) -> anyhow::Result<()> {
    let conn = globals.require_unix()?;
    let format = globals.format()?;

    let mut client = cpworker::new_client_with_timeout(&conn, globals.timeout)?;
    let info = client.info(globals.timeout)?;
    let _ = client.close();

    match format {
        crate::cli::Format::Jsonl => {
            println!("{}", serde_json::to_string(&info)?);
        }
        crate::cli::Format::Text => {
            println!("version          : {}", info.version);
            println!("pid              : {}", info.pid);
            println!("uptime           : {}s ({} sec)", info.uptime_sec, info.uptime_sec);
            println!(
                "started_at       : {}",
                info.started_at().format("%Y-%m-%dT%H:%M:%SZ")
            );
            println!("config_path      : {}", info.config_path);
            println!("working_dir      : {}", info.working_dir);
            println!("log_destination  : {}", info.log_destination);
        }
    }
    Ok(())
}
