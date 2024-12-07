# PyLog

## Project Overview

PyLog is a Python-based tool designed for parsing and analyzing web server log files. It provides in-depth insights into server access patterns, request distributions, and potential security threats by examining log entries.

## Features

### 1. IP Request Tracking
- Counts and sorts the number of requests made by each unique IP address
- Helps identify most active clients and potential traffic sources

### 2. Endpoint Analysis
- Identifies the most frequently accessed endpoint
- Provides insights into the most popular resources on the server

### 3. Suspicious Activity Detection
- Detects potential brute force login attempts
- Flags IP addresses with excessive failed login attempts
- Configurable threshold for suspicious activity

### 4. Comprehensive Reporting
- Displays analysis results in the terminal
- Generates a detailed CSV report
- Includes breakdown of:
  - Requests per IP
  - Most accessed endpoint
  - Suspicious login activities

## Prerequisites

- Python 3.8+

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/imakashy00/pylog.git
   cd pylog
   ```

2. Ensure you have Python 3.8 or higher installed:
   ```bash
   python3 --version
   ```

## Usage

### Basic Execution

```bash
python3 main.py
```

### Customizing Analysis

You can modify the script to:
- Change the failed login attempt threshold
- Analyze different log files
- Adjust detection criteria

### Example

```python
# In the script, modify the main() function or create a custom analyzer
log_file_path = 'your_log_file.log'
failed_login_threshold = 15  # Customize suspicious activity threshold
analyzer = LogAnalyzer(log_file_path, failed_login_threshold)
analyzer.display_results()
```

## Output

### Terminal Display
- Detailed breakdown of IP requests
- Most accessed endpoint
- Suspicious login activities

### CSV Report
The script generates `log_analysis_results.csv` with three sections:
1. Requests per IP
2. Most Accessed Endpoint
3. Suspicious Activity

## Security Considerations

- Use this tool for legitimate monitoring purposes
- Respect privacy and compliance regulations
- Do not use for unauthorized access monitoring



