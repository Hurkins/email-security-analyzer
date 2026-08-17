# Email Security Analyzer

Email Security Analyzer is a Python-based tool that analyzes email messages for potential security risks. It can inspect email headers, analyze attachments, and generate reports to help users understand why an email may be suspicious.

The project is intended for security researchers, developers, students, and organizations that want additional visibility into email security without relying solely on enterprise security platforms.

## Features

- IMAP IDLE monitoring for new emails
- Email header analysis
- SPF, DKIM, DMARC, and ARC validation
- Attachment analysis
- Polyglot file detection
- PDF JavaScript detection
- VBA macro detection
- ZIP bomb detection
- YARA rule scanning
- CVE pattern detection
- Security report generation

## How it Works

When running in monitoring mode the analyzer:

1. Connects to an IMAP server.
2. Enters the IMAP IDLE loop.
3. Waits for new email.
4. Performs header analysis.
5. Performs attachment analysis.
6. Generates a security report.
7. Returns to IDLE mode.


## Installation
```bash
git clone https://github.com/Hurkins/Email_Security_Analyzer.git

cd Email_Security_Analyzer
```

## Requirements
- python 3.11 or later
- dependencies listed in `requirements.txt`
```bash
pip install -r requirements.txt
```
## Usage

### How to run with IMAP

```bash 
python main.py  --setup
``` 

enter your email address 
```bash 
Enter your email address: youraddress@emailprovider.com
```
choose email provider using key arrows
```bash
? Select your email provider: Use arrow keys
    » Gmail
    Outlook
    Other
```

Enter the mailbox to be observed 
```bash
Mailbox to monitor: INBOX
```

Then enter your app password
```bash
Enter your app password:
```

that will get you straight to idle mode until a new message come then returns to idle mode

If at any point you want to run all your messages from the first message in your mailbox, use the
```bash
python main.py  --backfill
```

## Component Usage

The analysis components are designed to be used independently or together as part of the complete email security analysis workflow.

### Individual Components

The components can be used separately when only a specific type of analysis is required.

#### Header Analysis

The header analysis component can be run independently to analyze email headers and authentication information.

```bash
python header_analyzer.py /path/to/your/email.eml
```

#### Attachment Analysis

The attachment analysis component can be run independently to analyze email attachments for potentially malicious or suspicious content.

```bash
python extension_analyzer.py /path/to/your/attachment
```

### Complete Analysis Pipeline

The components can also be combined as part of the complete analysis pipeline.

```text
Email
  │
  ├── Header Analysis
  │
  └── Attachment Analysis
          │
          ↓
      Security Report
```
## Current Limitations

- Header risk scoring is still under development.
- Nested MIME attachment numbering is not yet implemented.

## Project Status

Version: 1.0-beta.0

This is the first public release of Email Security Analyzer.

The project is under active development, and new detection capabilities and improvements will continue to be added in future releases.

## Future Plans

- Intent analysis
- URL reputation analysis
- Improved header scoring
- HTML email analysis
- Enhanced reporting

## License

Copyright © 2026 Hurkins

This project is licensed under the GNU Affero General Public License v3.0. See the `LICENSE` file for details.

## Disclaimer

This project is intended to assist with email security analysis. It should not be considered a replacement for enterprise email security solutions or professional security practices.
