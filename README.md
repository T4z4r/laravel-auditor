# Laravel Auditor

A secure Laravel application scanner built with Python and PyQt6.

## Features

- **Web Scanner**: Scan remote Laravel applications for security vulnerabilities
- **Local Scanner**: Analyze local Laravel project files for security issues
- **Risk Assessment**: Automatic risk scoring based on detected vulnerabilities
- **Export Reports**: Export scan results in JSON, HTML, or CSV formats
- **Dark/Light Mode**: Toggle between themes for better usability

## Requirements

- Python 3.8+
- PyQt6
- requests
- beautifulsoup4
- qtawesome
- jinja2

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/T4Z4r/laravel-auditor.git
   cd laravel-auditor
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python laravel_auditor.py
   ```

## Troubleshooting

### PyQt6 Import Error on Windows
If you encounter `ImportError: DLL load failed while importing QtCore`, this is typically due to missing Visual C++ Redistributables.

**Solution:**
1. Download and install the Microsoft Visual C++ Redistributable for Visual Studio 2019 from:
   https://aka.ms/vs/16/release/vc_redist.x64.exe
2. Restart your computer after installation.
3. Try running the application again.

If the issue persists, try installing PyQt6 with binary wheels:
```bash
pip install --upgrade --force-reinstall PyQt6 --only-binary=all
```

## Usage

### Web Scanner
1. Enter the URL of the Laravel application
2. Click "Scan" to perform security analysis
3. View results in the Results tab

### Local Scanner
1. Browse and select a Laravel project folder
2. Click "Scan" to analyze local files
3. Review security findings

## Security Checks

- Laravel version detection
- PHP version identification
- .env file exposure detection
- Session cookie analysis
- Risk scoring based on vulnerabilities

## Export Options

- **JSON**: Structured data format
- **HTML**: Web-viewable report with styling
- **CSV**: Spreadsheet-compatible format

## Author

T4Z4R

## Version

1.0

## License

This project is open source. Please check the license file for details.