# tia-ti-IPReputationLookup
A command-line tool that queries multiple public IP reputation databases (e.g., AbuseIPDB, VirusTotal) and provides the per-service details for a given IP address. The code does not compute a consolidated score; it prints the fields each service returns. - Focused on Aggregates threat intelligence feeds from various open-source sources (e.g., AlienVault OTX, VirusTotal) and presents a unified view of indicators of compromise (IOCs) like IPs, domains, and hashes. Supports filtering, searching, and exporting data for integration with other security tools.

## Install
`git clone https://github.com/ShadowStrikeHQ/tia-ti-ipreputationlookup`

## Usage
`./tia-ti-ipreputationlookup [params]`

## Parameters
- `-h`: Show help message and exit
- `-o`: Output file to save results (JSON format).
- `--timeout`: Timeout in seconds for each service request (default: 30).

## Notes
Outcomes are tracked per service. A 404 from AbuseIPDB or VirusTotal means the indicator is unknown to that service and is reported as such, distinct from a failed lookup. An IPVoid page with no results table is reported as no data, not an error. If every service fails, has no record, or returns nothing, the tool prints no report and exits non-zero. An invalid IP address is a usage failure and exits non-zero. API keys are read from the ABUSEIPDB_API_KEY and VIRUSTOTAL_API_KEY environment variables and are sent in headers only.

## License
Copyright (c) ShadowStrikeHQ
