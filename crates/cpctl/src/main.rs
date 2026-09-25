//! `cpctl` — control utility for cpworker. Port of `cpctl/cmd`.

mod cli;
mod format;
mod info;
mod ping;
mod stats;

use clap::Parser;

use cli::{Cli, Command, Globals};

fn main() {
    let cli = Cli::parse();
    cpgolib::slogx::init_default(log::LevelFilter::Info);

    if let Err(e) = run(&cli) {
        log::error!("fail error={e}");
        std::process::exit(1);
    }
}

fn run(cli: &Cli) -> anyhow::Result<()> {
    let globals = Globals {
        unix: cli.unix.clone(),
        format: cli.format.clone(),
        timeout: cli.timeout,
    };
    match &cli.command {
        Command::Version => {
            println!("version: {}", env!("CARGO_PKG_VERSION"));
            println!();
            Ok(())
        }
        Command::Info => info::run(&globals),
        Command::Ping {
            count,
            interval,
            quiet,
        } => ping::run(&globals, *count, *interval, *quiet),
        Command::Stats { count, interval } => stats::run(&globals, *count, *interval),
    }
}
