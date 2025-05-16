import argparse
import requests
import json
import logging
import os
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# API Keys (Store securely, consider environment variables)
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")


def check_abuseipdb(ip_address):
    """
    Queries AbuseIPDB for IP reputation.
    Args:
        ip_address (str): The IP address to check.
    Returns:
        dict: A dictionary containing the AbuseIPDB results, or None if an error occurred.
    """
    if not ABUSEIPDB_API_KEY:
        logging.error("AbuseIPDB API key not set. Please set the ABUSEIPDB_API_KEY environment variable.")
        return None

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
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error querying AbuseIPDB: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from AbuseIPDB: {e}")
        return None


def check_virustotal(ip_address):
    """
    Queries VirusTotal for IP reputation.
    Args:
        ip_address (str): The IP address to check.
    Returns:
        dict: A dictionary containing the VirusTotal results, or None if an error occurred.
    """

    if not VIRUSTOTAL_API_KEY:
        logging.error("VirusTotal API key not set. Please set the VIRUSTOTAL_API_KEY environment variable.")
        return None

    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY,
        'Accept': 'application/json'
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error querying VirusTotal: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from VirusTotal: {e}")
        return None


def scrape_ipvoid(ip_address):
    """
    Scrapes IPVoid for IP reputation.
    Args:
        ip_address (str): The IP address to check.
    Returns:
        dict: A dictionary containing the IPVoid results, or None if an error occurred.
    """
    url = f'https://www.ipvoid.com/ip-blacklist-check/'
    data = {'ip': ip_address}
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }

    try:
        response = requests.post(url, data=data, headers=headers)
        response.raise_for_status()
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
        return results
    except requests.exceptions.RequestException as e:
        logging.error(f"Error scraping IPVoid: {e}")
        return None
    except Exception as e:
        logging.error(f"Error processing IPVoid response: {e}")
        return None


def aggregate_results(ip_address):
    """
    Aggregates the results from all reputation services.
    Args:
        ip_address (str): The IP address being checked.
    Returns:
        dict: A dictionary containing aggregated results.
    """

    abuseipdb_results = check_abuseipdb(ip_address)
    virustotal_results = check_virustotal(ip_address)
    ipvoid_results = scrape_ipvoid(ip_address)

    aggregated_data = {
        'ip_address': ip_address,
        'AbuseIPDB': abuseipdb_results,
        'VirusTotal': virustotal_results,
        'IPVoid': ipvoid_results
    }

    return aggregated_data


def print_results(results):
    """
    Prints the aggregated results in a user-friendly format.
    Args:
        results (dict): The aggregated results dictionary.
    """
    print(f"IP Reputation Report for: {results['ip_address']}")
    print("-" * 30)

    print("\nAbuseIPDB:")
    if results['AbuseIPDB']:
        data = results['AbuseIPDB']['data']
        print(f"  Confidence Score: {data['abuseConfidenceScore']}")
        print(f"  Total Reports: {data['totalReports']}")
        print(f"  Country Code: {data['countryCode']}")
        print(f"  Last Reported: {data['lastReported']}")
        print(f"  Is Whitelisted: {data['isWhitelisted']}")
    else:
        print("  Error or No Data Available")

    print("\nVirusTotal:")
    if results['VirusTotal']:
        data = results['VirusTotal']['data']
        attributes = data['attributes']
        print(f"  Reputation: {attributes.get('reputation', 'N/A')}")
        print("  Last Analysis Stats:")
        for k, v in attributes.get('last_analysis_stats', {}).items():
            print(f"    {k}: {v}")
    else:
        print("  Error or No Data Available")

    print("\nIPVoid:")
    if results['IPVoid']:
        print("  Blacklist Status:")
        for k, v in results['IPVoid'].items():
            print(f"    {k}: {v}")
    else:
        print("  Error or No Data Available")


def is_valid_ip(ip_address):
    """
    Validates if the given string is a valid IPv4 address.
    Args:
        ip_address (str): The string to validate.
    Returns:
        bool: True if the string is a valid IPv4 address, False otherwise.
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
        return

    results = aggregate_results(ip_address)

    if results:
        print_results(results)

        if args.output:
            try:
                with open(args.output, 'w') as outfile:
                    json.dump(results, outfile, indent=4)
                print(f"Results saved to {args.output}")
            except Exception as e:
                logging.error(f"Error saving results to file: {e}")
                print(f"Error: Could not save results to file: {e}")


    else:
        print("Error: Could not retrieve IP reputation information.")


if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Check the reputation of an IP address:
#    python tia_ti_IPReputationLookup.py 8.8.8.8

# 2. Check the reputation of an IP address and save the results to a file:
#    python tia_ti_IPReputationLookup.py 8.8.8.8 -o results.json