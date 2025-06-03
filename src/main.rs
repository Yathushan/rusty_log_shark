use std::collections::HashMap;
use std::fs::File; // For opening files
use std::io::{BufRead, BufReader}; // For buffered reading
use std::path::{Path, PathBuf};
use std::process;

use chrono::Timelike;
use chrono::{DateTime, NaiveDateTime, Utc};
use clap::Parser;
use colored::*;
use lazy_static::lazy_static;
use regex::Regex;
use serde::Deserialize;

lazy_static! {
    // A list of (Regex to find the timestamp, Chrono format string) tuples.
    // We will try these in order until one successfully parses.
    static ref TIMESTAMP_FORMATS: Vec<(Regex, &'static str)> = vec![
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

/// A simple CLI tool to analyse log files.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)] // Attributes for help message
struct CliArgs {
    /// One or more log file paths or directories to analyse.
    #[arg(required = true, num_args = 1..)] // Ensures at least one path is given
    paths: Vec<PathBuf>, // Changed to Vec<PathBuf> to handle multiple paths

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
struct Config {
    default_pattern: Option<String>,
    // We could add more config options here in the future
}

struct LogEntry {
    timestamp: DateTime<Utc>,
    original_line: String,
    source_path: PathBuf,
}

// Helper function to load and parse the config file
fn load_config() -> Option<Config> {
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
fn parse_timestamp(line: &str) -> Option<DateTime<Utc>> {
    for (regex, format_str) in TIMESTAMP_FORMATS.iter() {
        if let Some(captures) = regex.captures(line) {
            if let Some(timestamp_match) = captures.get(1) {
                // FIX #3: Use the modern, non-deprecated method for parsing
                if let Ok(naive_dt) =
                    NaiveDateTime::parse_from_str(timestamp_match.as_str(), format_str)
                {
                    // Assume UTC for naive datetimes. For timestamps without a year,
                    // chrono might default to a placeholder, so handling might be needed for real-world use.
                    // For now, we'll let chrono decide the year if not present.
                    return Some(naive_dt.and_utc());
                }
            }
        }
    }
    None // Return None if no format matches
}

// Helper function to parse a file and returns a list of LogEntry structs
fn parse_log_file(log_file_path: &Path, filter_regex: &Option<Regex>) -> Vec<LogEntry> {
    println!(
        "{} {}",
        "Processing file:".blue(),
        log_file_path.display().to_string().cyan()
    );

    let mut entries = Vec::new();
    let file = match File::open(log_file_path) {
        Ok(f) => f,
        Err(_) => return entries, // Return empty list if file can't be opened
    };

    let reader = BufReader::new(file);

    for line_result in reader.lines() {
        if let Ok(line) = line_result {
            // First, check if the line matches the filter pattern, if one is provided
            if let Some(re) = filter_regex {
                if !re.is_match(&line) {
                    continue; // Skip lines that don't match the pattern
                }
            }

            // Next, try to parse the timestamp from the line
            if let Some(timestamp) = parse_timestamp(&line) {
                entries.push(LogEntry {
                    timestamp,
                    original_line: line,
                    source_path: log_file_path.to_path_buf(),
                });
            }
        }
    }
    entries
}

// Helper function to parse the timestamp strings provided by the user via the CLI.
fn parse_cli_timestamp(s: &str) -> DateTime<Utc> {
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
fn highlight_matches(line: &str, re: &Regex) -> String {
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

fn main() {
    let args = CliArgs::parse();

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
        let mut last_path: Option<&PathBuf> = None;
        for entry in &all_entries {
            if last_path.map_or(true, |p| p != &entry.source_path) {
                report_lines.push(format!(
                    "\n// {}:",
                    entry.source_path.display().to_string().cyan()
                ));
                last_path = Some(&entry.source_path);
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
}
