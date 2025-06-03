# Log Shark 🦈

Log Shark is a command-line tool written in Rust for analysing, sorting, and filtering log files. It's designed to be fast, flexible, and easy to use for digging through logs from various sources.

## Features

- **Multi-source Parsing:** Analyse multiple files and entire directories at once.
- **Flexible Timestamp Recognition:** Automatically parses several common timestamp formats.
- **Powerful Filtering:**
    - Filter logs by a specific time window (`--after`, `--before`).
    - Filter logs using regular expression patterns (`--pattern`).
- **Chronological Sorting:** Merges all log entries from all sources into a single, chronologically sorted output.
- **Two Output Modes:**
    1.  **List View:** A detailed, sorted list of all matching log entries.
    2.  **Aggregation View:** Group log counts by `hour` or `day` using `--group-by`.
- **Match Highlighting:** Visually highlights the exact text that matches a regex pattern.
- **Configurable:** Use a `log_shark.toml` file to set a default regex pattern.
- **Save to File:** Save any report to a file with `--output <filename>`.

## Installation

1.  Ensure you have Rust and Cargo installed.
2.  Clone this repository: `git clone <your-repo-url>`
3.  Navigate into the directory: `cd log_shark`
4.  Build the project for release: `cargo build --release`
5.  The executable will be located at `./target/release/log_shark`.

## Usage

### Basic

```bash
# Analyse a single file
./target/release/log_shark /path/to/your.log

# Analyse all files in a directory
./target/release/log_shark ./my_logs/
```

### Filtering

```bash
# Find all lines containing "ERROR" or "WARN"
./target/release/log_shark ./my_logs/ -p "(ERROR|WARN)"

# Find all entries after a certain time
./target/release/log_shark ./my_logs/ --after "2025-06-01 10:00:00"
```

### Aggregation

```bash
# Group entries by hour and show the counts
./target/release/log_shark ./my_logs/ --group-by hour

# Group by day and show the matching lines for each group
./target/release/log_shark ./my_logs/ --group-by day --show-matches
```

### Configuration

Create a `log_shark.toml` file in the same directory you run the tool from to set a default pattern:

```toml
# log_shark.toml
default_pattern = "(ERROR|CRITICAL)"
```
