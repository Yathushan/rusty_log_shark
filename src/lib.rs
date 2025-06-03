// src/lib.rs

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process;

use chrono::{DateTime, NaiveDateTime, Timelike, Utc};
use clap::{ArgGroup, Parser};
use colored::*;
use lazy_static::lazy_static;
use rayon::prelude::*;
use regex::Regex;
use serde::Deserialize;

lazy_static! {
    // A list of (Regex to find the timestamp, Chrono format string) tuples.
    // We will try these in order until one successfully parses.
    static ref TIMESTAMP_FORMATS: Vec<(Regex, &'static str)> = vec![
        // Docker Format: {"level":"info",..."time":"2025-05-22T12:09:16Z",...}
        (Regex::new(r#""time":"([^"]+)""#).unwrap(), "%Y-%m-%dT%H:%M:%SZ"),
        // Format: [2025-06-01 19:33:40]
        (Regex::new(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]").unwrap(), "%Y-%m-%d %H:%M:%S"),
        // Format: Thu Jun 09 06:07:04 2005
        (Regex::new(r"(\w{3} \w{3} \s?\d{1,2} \d{2}:\d{2}:\d{2} \d{4})").unwrap(), "%a %b %e %H:%M:%S %Y"),
        // Format: 12-17 19:31:36.263 (assumes current year)
        (Regex::new(r"(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})").unwrap(), "%m-%d %H:%M:%S%.3f"),
        // Format: Jul  1 09:00:55 OR Dec 10 06:55:46 (assumes current year)
        (Regex::new(r"(\w{3} \s?\d{1,2} \d{2}:\d{2}:\d{2})").unwrap(), "%b %e %H:%M:%S"),
        // Format: 17/06/09 20:10:40
        (Regex::new(r"(\d{2}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})").unwrap(), "%d/%m/%y %H:%M:%S"),
    ];
}

/// A smart CLI tool to analyse, sort, and filter log files.
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
#[command(group(
    ArgGroup::new("input")
        .required(true)
        .args(["paths", "docker"]),
))]
pub struct CliArgs {
    /// One or more log file paths or directories to analyse.
    #[arg(required = true, num_args = 1..)] // Ensures at least one path is given
    paths: Vec<PathBuf>, // Changed to Vec<PathBuf> to handle multiple paths

    /// One or more Docker container names or IDs to read logs from.
    #[arg(long, short = 'd')]
    pub docker: Vec<String>,

    /// Optional REGEX pattern to search for in log lines.
    #[arg(short, long)]
    pattern: Option<String>, // Changed from 'keyword'

    /// Filter for logs after this timestamp (e.g., "2025-06-01 18:00:00").
    #[arg(long)]
    after: Option<String>,

    /// Filter for logs before this timestamp (e.g., "2025-06-01 20:00:00").
    #[arg(long)]
    before: Option<String>,

    /// Group log entries by a time unit (hour or day) and show counts.
    #[arg(long, value_parser = ["hour", "day"])]
    group_by: Option<String>,

    /// When grouping, show the actual log lines that fall into each group.
    #[arg(long)]
    show_matches: bool,

    /// Save the final report to a file instead of printing to the console.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Deserialize, Debug)]
pub struct Config {
    default_pattern: Option<String>,
    // We could add more config options here in the future
}

/// Represents a single parsed log entry with its timestamp and content.
#[derive(Debug)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub original_line: String,
    pub source: String,
}

// Helper function to load and parse the config file
pub fn load_config() -> Option<Config> {
    let config_filename = "log_shark.toml";
    match std::fs::read_to_string(config_filename) {
        Ok(content) => {
            // File exists, try to parse it
            match toml::from_str(&content) {
                Ok(config) => Some(config),
                Err(e) => {
                    // File is malformed, print an error and exit
                    eprintln!(
                        "{} '{}': {}",
                        "Error: Could not parse config file".red().bold(),
                        config_filename,
                        e
                    );
                    process::exit(1);
                }
            }
        }
        Err(_) => {
            // File doesn't exist or couldn't be read, which is fine. Just return None.
            None
        }
    }
}

// Helper function to parse a timestamp from a line using multiple formats
pub fn parse_timestamp(line: &str) -> Option<DateTime<Utc>> {
    for (regex, format_str) in TIMESTAMP_FORMATS.iter() {
        if let Some(captures) = regex.captures(line) {
            if let Some(timestamp_match) = captures.get(1) {
                // Try to parse the captured string with the corresponding format.
                // If it succeeds, return the DateTime immediately.
                if let Ok(naive_dt) =
                    NaiveDateTime::parse_from_str(timestamp_match.as_str(), format_str)
                {
                    return Some(naive_dt.and_utc());
                }
            }
        }
    }
    // If no format matched, return None.
    None
}

/// Helper function to parse an iterator of log lines into a vector of LogEntry structs.
pub fn parse_lines<'a>(
    lines: Vec<&'a str>, // We now take a Vec of string slices
    source: &str,
    filter_regex: &Option<Regex>,
) -> Vec<LogEntry> {
    lines
        .into_par_iter() // 1. Convert the vector into a parallel iterator
        .filter_map(|line| {
            // 2. Process each line in parallel
            // This closure runs on many threads at once.

            // First, check the filter pattern
            if let Some(re) = filter_regex {
                if !re.is_match(line) {
                    return None; // Skip if it doesn't match
                }
            }

            // Next, parse the timestamp
            if let Some(timestamp) = parse_timestamp(line) {
                // If successful, return a LogEntry
                Some(LogEntry {
                    timestamp,
                    original_line: line.to_string(),
                    source: source.to_string(),
                })
            } else {
                // If no timestamp found, discard the line
                None
            }
        })
        .collect() // 3. Collect the results from all threads back into a single Vec
}

/// Helper function to open a log file, read its lines, and send them to the core parser.
fn parse_log_file(log_file_path: &Path, filter_regex: &Option<Regex>) -> Vec<LogEntry> {
    eprintln!(
        "{} {}",
        "Processing file:".blue(),
        log_file_path.display().to_string().cyan()
    );

    if let Ok(file) = File::open(log_file_path) {
        let reader = BufReader::new(file);
        // We must collect lines into a Vec so the string data lives long enough.
        let lines: Vec<String> = reader.lines().filter_map(Result::ok).collect();
        // collect the lines into a Vec of &str before passing
        let line_slices: Vec<&str> = lines.iter().map(AsRef::as_ref).collect();
        parse_lines(
            line_slices,
            &log_file_path.display().to_string(),
            filter_regex,
        )
    } else {
        Vec::new() // Return empty vector if file can't be opened
    }
}

// Helper function to parse the timestamp strings provided by the user via the CLI.
pub fn parse_cli_timestamp(s: &str) -> DateTime<Utc> {
    // We expect a specific format from the user for the --after and --before flags.
    let format_str = "%Y-%m-%d %H:%M:%S";
    NaiveDateTime::parse_from_str(s, format_str)
        .unwrap_or_else(|err| {
            eprintln!(
                "{} '{}': {}",
                "Error: Invalid timestamp format for --after/--before flag"
                    .red()
                    .bold(),
                s,
                err
            );
            eprintln!("Please use the format: {}", "YYYY-MM-DD HH:MM:SS".yellow());
            process::exit(1);
        })
        .and_utc()
}

// Helper function to visualize matches in a string using ANSI escape codes.
pub fn highlight_matches(line: &str, re: &Regex) -> String {
    let mut result = String::new();
    let mut last_end = 0;

    for mat in re.find_iter(line) {
        // Append the part of the string before the match
        result.push_str(&line[last_end..mat.start()]);

        // Append the matched part, highlighted
        result.push_str(&mat.as_str().magenta().bold().to_string());

        last_end = mat.end();
    }

    // Append the rest of the string after the final match
    result.push_str(&line[last_end..]);

    result
}

/// Main entry point for the log analysis logic.
///
/// Takes parsed command-line arguments and executes the full
/// collection, filtering, sorting, and reporting workflow.
pub fn run(args: CliArgs) -> Result<(), Box<dyn std::error::Error>> {
    // --- NEW: CONFIGURATION LOGIC ---
    // 1. Load config from `log_shark.toml` if it exists
    let config = load_config();

    // 2. Determine the final pattern to use based on priority
    //    The .or() method on Option is perfect for this! It returns the first `Some` it finds.
    let pattern_to_use = args.pattern.or(config.and_then(|c| c.default_pattern));
    // .and_then() is used to safely get default_pattern from an Option<Config>

    // 3. Compile the final pattern
    let filter_regex = pattern_to_use.as_ref().map(|p| {
        Regex::new(p).unwrap_or_else(|e| {
            eprintln!("Error: Invalid regex pattern: {}", e);
            process::exit(1);
        })
    });

    let after_timestamp = args.after.as_deref().map(parse_cli_timestamp);
    let before_timestamp = args.before.as_deref().map(parse_cli_timestamp);

    let mut all_entries: Vec<LogEntry> = Vec::new();

    // PROGRESS messages now go to stderr using eprintln!
    eprintln!("{}", "--- Log Collection Starting ---".magenta().bold());
    for path_buf in &args.paths {
        if path_buf.is_file() {
            all_entries.extend(parse_log_file(path_buf.as_path(), &filter_regex));
        } else if path_buf.is_dir() {
            if let Ok(dir_entries) = std::fs::read_dir(path_buf) {
                for entry_result in dir_entries {
                    if let Ok(entry) = entry_result {
                        if entry.path().is_file() {
                            all_entries.extend(parse_log_file(&entry.path(), &filter_regex));
                        }
                    }
                }
            }
        }
    }

    // --- Process Docker containers (if any) ---
    for container in &args.docker {
        eprintln!(
            "{} {}",
            "Fetching logs for container:".blue(),
            container.cyan()
        );
        let output = std::process::Command::new("docker")
            .arg("logs")
            .arg(container)
            .output()?;

        if !output.status.success() {
            let error_message = String::from_utf8_lossy(&output.stderr);
            eprintln!(
                "{} '{}': {}",
                "Error fetching docker logs for".red().bold(),
                container,
                error_message
            );
            continue;
        }

        // Combine stdout and stderr to capture all logs.
        let mut combined_output = output.stdout;
        combined_output.extend_from_slice(&output.stderr);
        let logs_str = String::from_utf8_lossy(&combined_output);

        let lines: Vec<&str> = logs_str.lines().collect();

        all_entries.extend(parse_lines(lines, container, &filter_regex));
    }

    eprintln!(
        "\n{} {} log entries collected.",
        "---".magenta(),
        all_entries.len().to_string().yellow()
    );

    if let Some(after) = after_timestamp {
        eprintln!(
            "Filtering for entries after {}...",
            after.to_string().yellow()
        );
        all_entries.retain(|entry| entry.timestamp > after);
    }
    if let Some(before) = before_timestamp {
        eprintln!(
            "Filtering for entries before {}...",
            before.to_string().yellow()
        );
        all_entries.retain(|entry| entry.timestamp < before);
    }

    eprintln!("{}", "Sorting entries by timestamp...".blue());
    all_entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    // --- REPORT GENERATION ---
    // We will now build the report into a vector of strings.
    let mut report_lines: Vec<String> = Vec::new();

    if let Some(unit) = args.group_by {
        report_lines.push(format!("\n{}", "--- Aggregation Report ---".green().bold()));

        let mut groups: HashMap<DateTime<Utc>, Vec<&LogEntry>> = HashMap::new();
        for entry in &all_entries {
            let truncated_ts = match unit.as_str() {
                "hour" => entry
                    .timestamp
                    .with_minute(0)
                    .unwrap()
                    .with_second(0)
                    .unwrap()
                    .with_nanosecond(0)
                    .unwrap(),
                "day" => entry
                    .timestamp
                    .with_hour(0)
                    .unwrap()
                    .with_minute(0)
                    .unwrap()
                    .with_second(0)
                    .unwrap()
                    .with_nanosecond(0)
                    .unwrap(),
                _ => unreachable!(),
            };
            groups
                .entry(truncated_ts)
                .or_insert_with(Vec::new)
                .push(entry);
        }

        let mut sorted_keys: Vec<&DateTime<Utc>> = groups.keys().collect();
        sorted_keys.sort();

        for key in sorted_keys {
            if let Some(log_group) = groups.get(key) {
                let count = log_group.len();
                let format_str = if unit == "hour" {
                    "%Y-%m-%d %H:00"
                } else {
                    "%Y-%m-%d"
                };

                report_lines.push(format!(
                    "\n{:<25} {} {}",
                    key.format(format_str).to_string().cyan().bold(),
                    "|".green(),
                    format!("{} entries", count).yellow()
                ));

                if args.show_matches {
                    for entry in log_group {
                        let line_to_print = if let Some(re) = &filter_regex {
                            highlight_matches(&entry.original_line, re)
                        } else {
                            entry.original_line.clone()
                        };
                        report_lines.push(format!(
                            "  [{}] {}",
                            entry
                                .timestamp
                                .format("%Y-%m-%d %H:%M:%S")
                                .to_string()
                                .dimmed(),
                            line_to_print
                        ));
                    }
                }
            }
        }
    } else {
        report_lines.push(format!(
            "\n{} {} filtered and sorted entries.",
            "---".green(),
            all_entries.len().to_string().yellow()
        ));
        report_lines.push(format!("{}", "--- Log Output ---".green().bold()));
        let mut last_source: Option<&String> = None;
        for entry in &all_entries {
            if last_source.map_or(true, |p| p != &entry.source) {
                report_lines.push(format!("\n// {}:", entry.source.cyan()));
                last_source = Some(&entry.source);
            }
            let line_to_print = if let Some(re) = &filter_regex {
                highlight_matches(&entry.original_line, re)
            } else {
                entry.original_line.clone()
            };
            report_lines.push(format!(
                "[{}] {}",
                entry
                    .timestamp
                    .format("%Y-%m-%d %H:%M:%S")
                    .to_string()
                    .dimmed(),
                line_to_print
            ));
        }
    }
    report_lines.push(format!("\n{}", "----------------------".green().bold()));

    // --- FINAL OUTPUT HANDLING ---
    // Now, either print the report to the console or save it to a file.
    let final_report = report_lines.join("\n");

    if let Some(output_path) = args.output {
        eprintln!(
            "{} '{}'",
            "Saving report to".blue(),
            output_path.display().to_string().cyan()
        );
        match std::fs::write(&output_path, final_report) {
            Ok(_) => eprintln!("{}", "Report saved successfully.".green()),
            Err(e) => eprintln!(
                "{} '{}': {}",
                "Error: Could not write to file".red().bold(),
                output_path.display(),
                e
            ),
        }
    } else {
        // If no --output flag, print the report to the console
        println!("{}", final_report);
    }

    Ok(())
}
