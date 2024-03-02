# HealthUp2Date

This project is a collection of Python scripts that work together to monitor, analyze, and manage files in a system. It is especially useful for users who frequently download files from the internet and want to ensure they are not malicious.

## Components

- `main.py`: This is the entry point of the application. It uses multithreading to run two main functions: `clearCache` and `virusTotal`.

- `ClearCache.py`: This script defines the `clearCache` function, which clears the system's cache by deleting all files and directories in the temporary directory.

- `VirusTotal.py`: This script is the core of the project. It continuously monitors the Downloads directory for any changes. When a new or modified file is detected, it calculates the file's MD5 hash and submits it to the VirusTotal API for virus scanning.

- `threading.py`: This is a standard Python library used for multithreading. It is used in `main.py` to run the `clearCache` and `virusTotal` functions concurrently.

## Prerequisites

To use this project, you need:

- Python 3.x
- A `keys.json` file in the same directory as your Python script. This file should contain your VirusTotal API key in the following format:
- requests
- plyr

```json
{
    "virus_total": "your-api-key-here"
}
```

- Replace "your-api-key-here" with your actual VirusTotal API key.

## Usage
Run the `main.py` script in the same directory as your `keys.json` file. The script will start monitoring the Downloads directory for new or modified files and clear the system's cache concurrently.
