# tia-ti-IPReputationLookup
A command-line tool that queries multiple public IP reputation databases (AbuseIPDB, VirusTotal, and IPVoid) and provides the per-service details for a given IP address. The code does not compute a consolidated score; it prints the fields each service returns.

## Install
`git clone https://github.com/ShadowGuard-AI/tia-ti-ipreputationlookup`

## Usage
`python3 main.py 8.8.8.8`
`python3 main.py 8.8.8.8 -o results.json`

## Parameters
- `ip_address`: The IP address to check (required positional argument).
- `-h`: Show help message and exit
- `-o`: Output file to save results (JSON format).
- `--timeout`: Timeout in seconds for each service request (default: 30). Must be positive; a zero or negative value is a usage error and exits 2.

## Notes
Outcomes are tracked per service. A 404 from AbuseIPDB or VirusTotal means the indicator is unknown to that service and is reported as such, distinct from a failed lookup. An IPVoid page with no results table is reported as no data, not an error. If every service fails, has no record, or returns nothing, the tool prints no report and exits non-zero. The IP address must be strict dotted decimal form: four parts of ASCII digits, no signs or whitespace, no leading zeros except a single 0, each part at most 255; an invalid IP address is a usage failure and exits non-zero. API keys are read from the ABUSEIPDB_API_KEY and VIRUSTOTAL_API_KEY environment variables at lookup time and are sent in headers only. If an output file is requested and cannot be written, the tool exits 1.

## License
MIT License. See LICENSE.
