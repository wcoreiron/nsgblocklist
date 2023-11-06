import requests
import base64
import time
import azure.core.exceptions
import logging
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

console = Console()


GITHUB_TOKEN = "your_githubtoken"
GITHUB_USERNAME = "yourgithubusernamehere"
GITHUB_REPO_NAME = "yourgithubreponamehere"
GITHUB_FILE_PATH = "yourhithubfilepathere"
VIRUSTOTAL_API_KEYS = ["your_vt_api_key_here", "your_vt_api_key_here2","your_vt_api_key_here3"]
ABUSEIPDB_API_KEY = "your_abuseipdb_api_key_here"
AZURE_SUBSCRIPTION_ID = 'your_azure_subscription_id'
def api_key_generator():
    while True:
        for key in VIRUSTOTAL_API_KEYS:
            yield key

api_key_gen = api_key_generator()

def get_ip_ranges(url):
    response = requests.get(url)
    response.raise_for_status()  # Check if the request was successful
    ip_ranges = response.text.strip().split(',')  # Split by comma
    ip_ranges = list(set(ip_ranges))  # Remove duplicates by converting to set, then back to list
    return ip_ranges

def analyze_ip_with_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": next(api_key_gen)}
    response = requests.get(url, headers=headers)
    response.raise_for_status()  # This will raise an exception if the request was unsuccessful
    return response.json()

def check_ip_location(ip, vt_data=None):
    try:
        url = f"https://ipapi.co/{ip}/json/"
        response = requests.get(url)
        response.raise_for_status()
        location_data = response.json()
        country_name = location_data.get('country_name', 'Unknown')
        country_code = location_data.get('country', '').upper()  # Ensure country code is in the correct format
        return country_name, country_code
    except requests.exceptions.HTTPError as err:
        if response.status_code == 429 and vt_data:
            country_name = vt_data.get('data', {}).get('attributes', {}).get('country_name', 'Unknown')
            country_code = vt_data.get('data', {}).get('attributes', {}).get('country', '').upper()
        else:
            logging.error(f"Failed to get location data for IP {ip}: {err}")
            country_name, country_code = 'Unknown', ''
        return country_name, country_code

def get_ip_range_from_virustotal(vt_data):
    return vt_data.get('data', {}).get('attributes', {}).get('network', '')

def check_ip_with_abuseipdb(ip):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()  # This will raise an exception if the request was unsuccessful
    return response.json()
def update_github_file(new_entry, commit_message):
    url = f"https://api.github.com/repos/{GITHUB_USERNAME}/{GITHUB_REPO_NAME}/contents/{GITHUB_FILE_PATH}"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()  # This will raise an exception if the request was unsuccessful
    file_sha = response.json()["sha"]

    existing_content = base64.b64decode(response.json()["content"]).decode("utf-8").strip()
    if new_entry not in existing_content:
        if existing_content:
            existing_content += ","
        existing_content += new_entry

    encoded_content = base64.b64encode(existing_content.encode("utf-8")).decode("utf-8")
    update_data = {
        "message": commit_message,
        "content": encoded_content,
        "sha": file_sha
    }
    response = requests.put(url, headers=headers, json=update_data)
    response.raise_for_status()  # This will raise an exception if the request was unsuccessful
    print(f"Successfully updated file on GitHub with message: {commit_message}")

def get_existing_rules(network_client, resource_group, nsg_name, rule_name):
    try:
        security_rule = network_client.security_rules.get(resource_group, nsg_name, rule_name)
        return security_rule.source_address_prefixes
    except Exception as e:
        print(f"Error retrieving IPs from {nsg_name}: {e}")
        return []

def update_ip_blacklist(network_client, resource_group, nsg_name, base_rule_name, new_ip_ranges):
    existing_ip_ranges = get_existing_rules(network_client, resource_group, nsg_name, base_rule_name)
    combined_ip_ranges = list(set(existing_ip_ranges + new_ip_ranges))  # Combine and deduplicate IPs
    
    MAX_IP_RANGES_PER_RULE = 250
    num_rules_created = 0
    for i in range(0, len(combined_ip_ranges), MAX_IP_RANGES_PER_RULE):
        chunk = combined_ip_ranges[i:i+MAX_IP_RANGES_PER_RULE]
        rule_name = f"{base_rule_name}{num_rules_created if num_rules_created > 0 else ''}"
        params = {
            "protocol": "*",
            "source_address_prefixes": chunk,
            "destination_address_prefix": "*",
            "source_port_range": "*",
            "destination_port_range": "*",
            "access": "Deny",
            "priority": 100 + num_rules_created,
            "direction": "Inbound",
        }
        result = network_client.security_rules.begin_create_or_update(
            resource_group,
            nsg_name,
            rule_name,
            params
        )
        result.wait()
        print(f"Successfully updated {rule_name} in {nsg_name}")
        num_rules_created += 1

def generate_abuse_confidence_bar(score, max_score=100, bar_length=20):
    filled_length = int(round(bar_length * score / float(max_score)))
    bar = '█' * filled_length + '-' * (bar_length - filled_length)
    return f"|{bar}| {score}%"
def flag_unicode(country_code):
    if not country_code:  # If country code is None or empty, return an empty string
        return ''
    # Convert the country code into its regional indicator symbols
    flag = ''.join(chr(0x1F1A5 + ord(c)) for c in country_code)
    return flag
def main():
    url = "https://raw.githubusercontent.com/your_username/your_repo/main/ip_blocklist.txt"
    ip_ranges = get_ip_ranges(url)
    console.print(f"Number of IPs fetched out of 250: {len(ip_ranges)}", style="bold blue")

    ip_to_analyze = console.input("Please enter the IP you want to analyze: ")

    with Progress() as progress:
        vt_data_task = progress.add_task("[cyan]Analyzing with VirusTotal...", total=100)
        vt_data = analyze_ip_with_virustotal(ip_to_analyze)
        progress.update(vt_data_task, completed=100)

    malicious_flags = vt_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
    if malicious_flags > 0:
        console.print(f"🔴 IP {ip_to_analyze} has [bold red]{malicious_flags} malicious flags[/bold red] on VirusTotal!")
    else:
        console.print(f"✅ IP {ip_to_analyze} has no malicious flags on VirusTotal.", style="green")

    with Progress() as progress:
        abuseipdb_task = progress.add_task("[cyan]Checking with AbuseIPDB...", total=100)
        abuseipdb_data = check_ip_with_abuseipdb(ip_to_analyze)
        progress.update(abuseipdb_task, completed=100)

    abuse_reports = abuseipdb_data.get('data', {}).get('totalReports', 0)
    abuse_confidence_score = abuseipdb_data.get('data', {}).get('abuseConfidenceScore', 0)
    confidence_bar = generate_abuse_confidence_bar(abuse_confidence_score)
    console.print(f"🔴 IP {ip_to_analyze} has been reported [bold red]{abuse_reports} times[/bold red] on AbuseIPDB.")
    console.print(f"🔴 Abuse Confidence Score: {confidence_bar}")

    country_name, country_code = check_ip_location(ip_to_analyze, vt_data)
    flag = flag_unicode(country_code)
    console.print(f"IP {ip_to_analyze} is from {country_name} {flag}.", style="bold green")

    decision = console.input("Do you want to add this specific IP or the whole range to GitHub? (Enter 'IP' or 'range'): ").lower()
    ip_range = get_ip_range_from_virustotal(vt_data)

    if decision == "ip":
        update_content = ip_to_analyze
        commit_message = f"Added IP {ip_to_analyze} to the blocklist"
    elif decision == "range" and ip_range:
        update_content = ip_range
        commit_message = f"Added IP range {ip_range} to the blocklist"

    if decision in ["ip", "range"]:
        with Progress() as progress:
            github_update_task = progress.add_task("[cyan]Updating GitHub...", total=100)
            update_github_file(update_content, commit_message)
            progress.update(github_update_task, completed=100)
            console.print(f"Successfully updated file on GitHub with message: [green]{commit_message}[/green]")

    ip_ranges = get_ip_ranges(url)
    console.print(f"Updated number of IPs fetched: [bold]{len(ip_ranges)}[/bold]", style="magenta")

    nsg_decision = console.input(f"Do you want to block {ip_range if decision == 'range' else ip_to_analyze} in your NSGs? (yes/no): ").lower()
    if nsg_decision == "yes":
        credential = DefaultAzureCredential()
        network_client = NetworkManagementClient(credential, AZURE_SUBSCRIPTION_ID)
        nsgs_to_update = [
             ("your_resource_group_name", "your_nsg_name", "ip_blacklist_rule_name"),
            # ... (rest of your provided nsgs_to_update list) ...
        ]
        for resource_group, nsg_name, base_rule_name in nsgs_to_update:
            console.print(f"\nUpdating NSG '[bold]{nsg_name}[/bold]' in resource group '[bold]{resource_group}[/bold]' with rule '[bold]{base_rule_name}[/bold]'...")
            new_ip_ranges = [ip_range] if decision == 'range' else [ip_to_analyze]
            update_ip_blacklist(network_client, resource_group, nsg_name, base_rule_name, new_ip_ranges)
            console.print(f"Successfully updated [bold green]{base_rule_name}[/bold green] in [bold blue]{nsg_name}[/bold blue]")

if __name__ == "__main__":
    main()
