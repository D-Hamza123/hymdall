# hymdall

## Overview
hymdall is a utility designed to analyze and process log files to identify specific patterns, anomalies, or security-related events. It is particularly useful for system administrators, security analysts, and developers who need to monitor and investigate system activities.

## How It Works
hymdall operates by scanning log files for predefined patterns, anomalies, or suspicious activities. The tool uses Sigma rules to define these patterns, making it highly customizable and adaptable to various use cases. Here's a high-level overview of its workflow:

1. **Log File Parsing**: hymdall reads log files from the `sample-logs/` directory, including authentication logs and web logs.
2. **Pattern Matching**: The tool applies predefined Sigma rules to detect specific threats, such as brute force attacks or unauthorized access attempts.
3. **Anomaly Detection**: It identifies unusual patterns in log data, such as repeated failed login attempts or access to sensitive web paths.
4. **Correlation Analysis**: hymdall correlates events across multiple logs to provide a comprehensive view of potential security incidents.
5. **Reporting**: The results of the analysis are displayed in the terminal, highlighting any detected threats or anomalies.

## Features
- **Log Analysis**: Processes log files to extract meaningful information.
- **Authentication Log Monitoring**: Detects failed login attempts and alerts on repeated suspicious activity.
- **Web Log Monitoring**: Identifies suspicious access to sensitive paths and tracks HTTP activity.
- **Sigma Rule Integration**: Includes predefined Sigma rules for detecting specific threats.
- **Customizable**: Easily extendable to include additional patterns, Sigma rules, or analysis techniques.

## File Structure
- `LICENSE`: Contains the MIT License for the project.
- `README.md`: Documentation for the project.
- `hymdall.py`: The main script for processing log files.
- `sample-logs/`: Directory containing sample log files.
  - `auth logs/`: Contains authentication log samples.
    - `auth-1.log`
    - `auth-2.log`
    - `auth-3.log`
  - `web logs/`: Contains web log samples.
    - `web-log1.log`
- `sigma-rules/`: Directory containing Sigma rules for threat detection.
  - `correlation.yaml`: Sigma rule for correlating multiple events.
  - `ssh-brute-force.yaml`: Sigma rule for detecting SSH brute force attacks.
  - `ssh-brute-force-correlation.yaml`: Sigma rule for correlating SSH brute force attacks.
  - `web-detection.yaml`: Sigma rule for detecting suspicious web activity.

## Usage

### Prerequisites
Ensure you have Python installed on your system. This tool is compatible with Python 3.x.

### Running the Tool
1. Clone the repository to your local machine:
   ```bash
   git clone https://github.com/D-Hamza123/hymdall.git
   ```
2. Navigate to the project directory:
   ```bash
   cd hymdall
   ```
3. Run the main script to process authentication and web logs:
   ```bash
   python3 hymdall.py
   ```

The script will automatically process all logs in the `sample-logs/auth logs/` and `sample-logs/web logs/` directories.

### Using Arguments
hymdall supports command-line arguments to customize its behavior. Below is the general syntax for running the tool with arguments:

```bash
python3 hymdall.py [options]
```

#### Available Arguments
- `--auth-logs <path>`: Specify the path to the directory containing authentication logs. Default is `sample-logs/auth logs/`.
- `--web-logs <path>`: Specify the path to the directory containing web logs. Default is `sample-logs/web logs/`.
- `--sigma-rules <path>`: Specify the path to the directory containing Sigma rules. Default is `sigma-rules/`.
- `--output <path>`: Specify the path to save the analysis report. If not provided, results are displayed in the terminal.
- `--verbose`: Enable verbose mode for detailed logging during execution.

#### Example Commands
1. Analyze logs using default directories:
   ```bash
   python3 hymdall.py
   ```

2. Specify custom directories for logs and Sigma rules:
   ```bash
   python3 hymdall.py --auth-logs /path/to/auth-logs --web-logs /path/to/web-logs
   ```

### Example Use Cases
- **System Monitoring**: Use hymdall to monitor authentication logs for failed login attempts or brute force attacks.
- **Web Security**: Analyze web server logs to detect unauthorized access to sensitive endpoints.
- **Incident Investigation**: Correlate events across multiple logs to investigate potential security incidents.
- **Custom Threat Detection**: Extend the tool with your own Sigma rules to detect specific threats relevant to your environment.

## Extending the Tool
To add new patterns, Sigma rules, or analysis techniques:
1. Open `hymdall.py` in a text editor.
2. Locate the section where patterns or Sigma rules are defined or analysis logic is implemented.
3. Add your custom logic or rules.

## Contributing
Contributions are welcome! Feel free to submit issues or pull requests on the project's repository.
