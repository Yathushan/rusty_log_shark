// src/main.rs

use clap::Parser;
use colored::Colorize;
use log_shark::{CliArgs, run};

fn main() {
    // 1. Parse the command-line arguments
    let args = CliArgs::parse();

    // 2. Call the main logic function from our library
    if let Err(e) = run(args) {
        // 3. If the run function returns an error, print it and exit
        eprintln!("{} {}", "Application error:".red().bold(), e);
        std::process::exit(1);
    }
}
