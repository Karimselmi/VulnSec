import re
import nmap
import requests
import argparse
import logging
import signal
import sys
import subprocess
from datetime import datetime

# Handle Ctrl+C gracefully
def signal_handler(sig, frame):
    print("\n\n[!] Exiting... Scan terminated by user.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Banner with a big name in blue color
def print_banner():
    banner = """
    \033[94m
    ========================================
      ██▒   █▓ █    ██  ██▓     ███▄    █   ██████ ▓█████  ▄████▄  
    ▓██░   █▒ ██  ▓██▒▓██▒     ██ ▀█   █ ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
     ▓██  █▒░▓██  ▒██░▒██░    ▓██  ▀█ ██▒░ ▓██▄   ▒███   ▒▓█    ▄ 
      ▒██ █░░▓▓█  ░██░▒██░    ▓██▒  ▐▌██▒  ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
       ▒▀█░  ▒▒█████▓ ░██████▒▒██░   ▓██░▒██████▒▒░▒████▒▒ ▓███▀ ░
       ░ ▐░  ░▒▓▒ ▒ ▒ ░ ▒░▓  ░░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ░▒ ▒  ░
       ░ ░░  ░░▒░ ░ ░ ░ ░ ▒  ░░ ░░   ░ ▒░░ ░▒  ░ ░ ░ ░  ░  ░  ▒   
         ░░   ░░░ ░ ░   ░ ░      ░   ░ ░ ░  ░  ░     ░   ░        
          ░     ░         ░  ░         ░       ░     ░  ░░ ░      
         ░                                               ░           
    ----------------------------------------
         VulnSec - Vulnerability Scanner     
    ========================================
    \033[0m
    """
    print(banner)

# Usage instructions to show how the user should run the tool
def print_usage():
    usage = """
    Usage: 
    VulnSec [OPTION] [TARGET_URL]

    Options:
    -v  Perform vulnerability scan
    -p  Perform port scanning (quick scan)
    -H  Check HTTP headers
    -S  Test for SQL Injection

    Example:
    VulnSec: -p https://example.com
    """
    print(usage)

# Description about the tool
def print_description():
    description = """
    \033[94m VulnSec \033[0m is a Python-based vulnerability scanner designed to help identify potential security risks in websites. 
    It allows scanning for open ports, SQL injection vulnerabilities, HTTP header security, and general vulnerabilities using Nmap.
    """
    print(description)

# Function to validate the URL format
def is_valid_url(url):
    regex = re.compile(
        r'^(https?://)?'  # http:// or https://
        r'([a-zA-Z0-9.-]+(\.[a-zA-Z]{2,})+)'  # domain name
        r'(:[0-9]{1,5})?'  # optional port
        r'(/.*)?$'  # path
    )
    return re.match(regex, url) is not None

# Function to scan for open ports using nmap (quick scan on common ports)
def scan_ports(target):
    nm = nmap.PortScanner()
    print(f"\n[*] Scanning {target} for open ports (quick scan)...\n")
    
    try:
        nm.scan(target, '1-1000', arguments='-sV --open')  # Scan common ports with version detection
        for host in nm.all_hosts():
            print(f"Host: {host} ({nm[host].hostname()})")
            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}")
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    print(f"Port {port} is {state}")
                    if state == 'open':
                        print(f"Service: {nm[host][proto][port]['name']}")
    except Exception as e:
        print(f"[!] Error during port scan: {e}")

# Function to check HTTP headers for security-related information
def check_http_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers
        print("\n--- HTTP Headers ---")
        for key, value in headers.items():
            print(f"{key}: {value}")

        # Check for some common security headers
        if 'X-Frame-Options' not in headers:
            print("X-Frame-Options is missing! Possible Clickjacking vulnerability.")
        if 'Content-Security-Policy' not in headers:
            print("Content-Security-Policy is missing! Possible XSS vulnerabilities.")
        if 'Strict-Transport-Security' not in headers:
            print("Strict-Transport-Security is missing! The site may be vulnerable to MITM attacks.")
        if 'Server' in headers:
            print(f"\nServer Information: {headers['Server']}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching URL: {e}")

# Function to check for SQL injection vulnerabilities using SQLMap
def check_sql_injection(url):
    print(f"Running SQL Injection test on {url} using SQLMap...")
    try:
        # Call SQLMap using subprocess to automate the scan
        subprocess.run(['sqlmap', '-u', url, '--batch'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] SQLMap scan failed: {e}")

# Logging the output to a file for documentation
def setup_logging():
    log_filename = f"vulnsec_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    logging.basicConfig(filename=log_filename, level=logging.INFO, 
                        format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    logging.info("VulnSec Scan Started")

def log_result(result):
    logging.info(result)

# Main function to tie all parts together
def vulnsec(url, scan_ports_flag, check_headers_flag, sql_injection_flag):
    if not is_valid_url(url):
        print(f"Invalid URL: {url}")
        return
    
    # Extract the domain from the URL for scanning
    target = url.split("//")[-1].split("/")[0]
    
    # Log the target
    setup_logging()
    log_result(f"Scanning Target: {target}")
    
    # Run the selected tests
    if scan_ports_flag:
        scan_ports(target)
    
    if check_headers_flag:
        check_http_headers(url)
    
    if sql_injection_flag:
        check_sql_injection(url)

# Entry point of the script using argparse for command-line arguments
if __name__ == "__main__":
    # Show the banner and description first
    print_banner()
    print_description()
    print_usage()
    
    # Take user input in the form of "VulnSec: -flag URL"
    user_input = input("VulnSec: ")
    args = user_input.split()
    
    if len(args) < 2:
        print("Error: Invalid input format. Example: VulnSec: -p https://example.com")
    else:
        flag = args[0]
        url = args[1]
        
        # Map flags to functions
        scan_ports_flag = flag == "-p"
        check_headers_flag = flag == "-H"
        sql_injection_flag = flag == "-S"
        vulnerability_scan_flag = flag == "-v"
        
        if vulnerability_scan_flag:
            print("Vulnerability scanning is not implemented yet.")
        else:
            vulnsec(url, scan_ports_flag, check_headers_flag, sql_injection_flag)
