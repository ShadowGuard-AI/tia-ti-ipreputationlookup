import argparse
import requests
import json
import logging
import os
import sys
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# API Keys (Store securely, consider environment variables)
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")

# Per-service outcomes: "ok" (data returned), "unknown" (the service answered
# 404, the indicator is unknown to it), "no_data" (the service answered but
# held no result), "error" (the lookup failed or the payload was malformed),
# and "not_configured" (no API key was set).
NO_DATA_OUTCOMES = ("unknown", "no_data", "error", "not_configured")


def check_abuseipdb(ip_address, timeout=30):
    """
    Queries AbuseIPDB for IP reputation.
    Returns:
        tuple: (outcome, dict or None). A 404 is reported as "unknown",
        distinct from a failed lookup.
    """
    if not ABUSEIPDB_API_KEY:
        logging.error("AbuseIPDB API key not set. Please set the ABUSEIPDB_API_KEY environment variable.")
        return "not_configured", None

    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': 90  # Configuration to change the maximum report age
    }
    headers = {
        'Key': ABUSEIPDB_API_KEY,
        'Accept': 'application/json'
    }

    try:
        response = requests.get(url, params=params, headers=headers, timeout=timeout)
    except requests.exceptions.RequestException as e:
        logging.error(f"Error querying AbuseIPDB: {e}")
        return "error", None

    if response.status_code == 404:
        logging.info(f"AbuseIPDB has no record of {ip_address} (HTTP 404).")
        return "unknown", None
    if response.status_code != 200:
        logging.error(f"AbuseIPDB returned HTTP {response.status_code}.")
        return "error", None
    try:
        payload = response.json()
    except ValueError as e:
        logging.error(f"Error decoding JSON from AbuseIPDB: {e}")
        return "error", None
    if not isinstance(payload, dict) or 'data' not in payload:
        logging.error("Malformed AbuseIPDB response: no data key.")
        return "error", None
    return "ok", payload


def check_virustotal(ip_address, timeout=30):
    """
    Queries VirusTotal for IP reputation.
    Returns:
        tuple: (outcome, dict or None). A 404 is reported as "unknown",
        distinct from a failed lookup.
    """
    if not VIRUSTOTAL_API_KEY:
        logging.error("VirusTotal API key not set. Please set the VIRUSTOTAL_API_KEY environment variable.")
        return "not_configured", None

    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY,
        'Accept': 'application/json'
    }

    try:
        response = requests.get(url, headers=headers, timeout=timeout)
    except requests.exceptions.RequestException as e:
        logging.error(f"Error querying VirusTotal: {e}")
        return "error", None

    if response.status_code == 404:
        logging.info(f"VirusTotal has no record of {ip_address} (HTTP 404).")
        return "unknown", None
    if response.status_code != 200:
        logging.error(f"VirusTotal returned HTTP {response.status_code}.")
        return "error", None
    try:
        payload = response.json()
    except ValueError as e:
        logging.error(f"Error decoding JSON from VirusTotal: {e}")
        return "error", None
    if not isinstance(payload, dict) or 'data' not in payload:
        logging.error("Malformed VirusTotal response: no data key.")
        return "error", None
    return "ok", payload


def scrape_ipvoid(ip_address, timeout=30):
    """
    Scrapes IPVoid for IP reputation.
    Returns:
        tuple: (outcome, dict or None). A results page with no results
        table is "no_data", not an error.
    """
    url = 'https://www.ipvoid.com/ip-blacklist-check/'
    data = {'ip': ip_address}
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }

    try:
        response = requests.post(url, data=data, headers=headers, timeout=timeout)
    except requests.exceptions.RequestException as e:
        logging.error(f"Error scraping IPVoid: {e}")
        return "error", None

    if response.status_code != 200:
        logging.error(f"IPVoid returned HTTP {response.status_code}.")
        return "error", None
    try:
        soup = BeautifulSoup(response.content, 'html.parser')
        table = soup.find('table', {'class': 'table table-bordered'})

        results = {}
        if table:
            rows = table.find_all('tr')
            for row in rows:
                cells = row.find_all('td')
                if len(cells) == 2:
                    name = cells[0].text.strip()
                    status = cells[1].text.strip()
                    results[name] = status
        if not results:
            logging.info(f"IPVoid returned no results table for {ip_address}.")
            return "no_data", {}
        return "ok", results
    except Exception as e:
        logging.error(f"Error processing IPVoid response: {e}")
        return "error", None


def aggregate_results(ip_address, timeout=30):
    """
    Aggregates the results from all reputation services, tracking the
    outcome of each service separately from its payload.
    """
    abuse_outcome, abuseipdb_results = check_abuseipdb(ip_address, timeout=timeout)
    vt_outcome, virustotal_results = check_virustotal(ip_address, timeout=timeout)
    ipvoid_outcome, ipvoid_results = scrape_ipvoid(ip_address, timeout=timeout)

    aggregated_data = {
        'ip_address': ip_address,
        'AbuseIPDB': abuseipdb_results,
        'VirusTotal': virustotal_results,
        'IPVoid': ipvoid_results,
        'service_status': {
            'AbuseIPDB': abuse_outcome,
            'VirusTotal': vt_outcome,
            'IPVoid': ipvoid_outcome
        }
    }

    return aggregated_data


def _status_line(outcome):
    return {
        "unknown": "  Indicator unknown to this service (no record, HTTP 404)",
        "no_data": "  No data returned by this service",
        "error": "  Lookup failed for this service",
        "not_configured": "  Not queried: API key not set",
    }.get(outcome, "  Error or No Data Available")


def print_results(results):
    """
    Prints the aggregated results in a user-friendly format. All payload
    lookups are guarded, so a response missing expected keys prints a
    per-service line instead of crashing.
    """
    status = results.get('service_status', {})
    print(f"IP Reputation Report for: {results['ip_address']}")
    print("-" * 30)

    print("\nAbuseIPDB:")
    payload = results.get('AbuseIPDB')
    if status.get('AbuseIPDB') == "ok" and isinstance(payload, dict):
        data = payload.get('data') or {}
        print(f"  Confidence Score: {data.get('abuseConfidenceScore', 'N/A')}")
        print(f"  Total Reports: {data.get('totalReports', 'N/A')}")
        print(f"  Country Code: {data.get('countryCode', 'N/A')}")
        print(f"  Last Reported: {data.get('lastReported', 'N/A')}")
        print(f"  Is Whitelisted: {data.get('isWhitelisted', 'N/A')}")
    else:
        print(_status_line(status.get('AbuseIPDB')))

    print("\nVirusTotal:")
    payload = results.get('VirusTotal')
    if status.get('VirusTotal') == "ok" and isinstance(payload, dict):
        data = payload.get('data') or {}
        attributes = data.get('attributes') or {}
        print(f"  Reputation: {attributes.get('reputation', 'N/A')}")
        print("  Last Analysis Stats:")
        for k, v in (attributes.get('last_analysis_stats') or {}).items():
            print(f"    {k}: {v}")
    else:
        print(_status_line(status.get('VirusTotal')))

    print("\nIPVoid:")
    payload = results.get('IPVoid')
    if status.get('IPVoid') == "ok" and isinstance(payload, dict) and payload:
        print("  Blacklist Status:")
        for k, v in payload.items():
            print(f"    {k}: {v}")
    else:
        print(_status_line(status.get('IPVoid')))


def is_valid_ip(ip_address):
    """
    Validates if the given string is a valid IPv4 address.
    """
    try:
        parts = ip_address.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not 0 <= int(part) <= 255:
                return False
        return True
    except ValueError:
        return False


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description='IP Reputation Lookup Tool')
    parser.add_argument('ip_address', help='The IP address to check')
    parser.add_argument('-o', '--output', help='Output file to save results (JSON format)')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout in seconds for each service request (default: 30)')
    return parser


def main():
    """
    Main function to execute the IP reputation lookup.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    ip_address = args.ip_address

    if not is_valid_ip(ip_address):
        logging.error("Invalid IP address format.")
        print("Error: Invalid IP address format.")
        sys.exit(1)

    results = aggregate_results(ip_address, timeout=args.timeout)
    status = results.get('service_status', {})

    if all(outcome in NO_DATA_OUTCOMES for outcome in status.values()):
        # Every service failed, had no record, or returned nothing: no
        # report verdict was earned.
        print(f"No reputation data could be retrieved for {ip_address}.")
        for name, outcome in status.items():
            print(f"  {name}:{_status_line(outcome)}")
        sys.exit(1)

    print_results(results)

    if args.output:
        try:
            with open(args.output, 'w') as outfile:
                json.dump(results, outfile, indent=4)
            print(f"Results saved to {args.output}")
        except Exception as e:
            logging.error(f"Error saving results to file: {e}")
            print(f"Error: Could not save results to file: {e}")


if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Check the reputation of an IP address:
#    python tia_ti_IPReputationLookup.py 8.8.8.8
#
# 2. Check the reputation of an IP address and save the results to a file:
#    python tia_ti_IPReputationLookup.py 8.8.8.8 -o results.json
