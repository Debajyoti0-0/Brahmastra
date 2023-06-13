import nmap
import requests
import os
import socket
import subprocess
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import builtwith
from colorizor import COLOR,STYLE
from banner import banner
import signal
import sys



def signal_handler(signal, frame):
        os.system('clear')
        banner()
        print(COLOR.YELLOW + "\n \n [^] Exiting the program...Goodbye! 👋"+ COLOR.WHITE)
        sys.exit()

# Register the signal handler function
signal.signal(signal.SIGINT, signal_handler)


# OSINT Analysis
def find_social_media_profiles():
    os.system('clear')
    banner()
    print(COLOR.PURPLE + "\n=== OSINT Analyzer ==="+ COLOR.WHITE)
    target = input(COLOR.LIGHT_CYAN + "[?] Enter the target username: "+ COLOR.WHITE)
    print(COLOR.LIGHT_GREEN + "\n[+] Searching for social media profiles...\n"+COLOR.WHITE)

    # Run Social-Analyzer tool
    command = f"social-analyzer --username {target} --metadata --top 50"
    output = os.popen(command).read()

    print(output)

# Information Gather
def gather_information():
    os.system('clear')
    banner()
    print(COLOR.PURPLE + "\n=== Gather Information ==="+ COLOR.WHITE)
    target = input(COLOR.LIGHT_CYAN + "[?] Enter the target URL or IP: "+ COLOR.WHITE)
    print(COLOR.LIGHT_GREEN + "\n[+] Gathering information...\n"+COLOR.WHITE)

    # Perform WHOIS lookup
    print(COLOR.GREEN + "[*] WHOIS Information:"+COLOR.WHITE)
    os.system('whois {}'.format(target))

    # Perform DNS lookup
    print(COLOR.GREEN + "\n[*] DNS Information:"+COLOR.WHITE)
    dns_url = f"https://api.hackertarget.com/dnslookup/?q={target}"
    response = requests.get(dns_url)
    print(response.text)

    # Perform GEOIP lookup
    print(COLOR.GREEN + "\n[*] GEOIP Information:"+ COLOR.WHITE)
    dns_url = f"http://api.hackertarget.com/geoip/?q={target}"
    response = requests.get(dns_url)
    print(response.text)

    # Perform Subnet Calculator
    print(COLOR.GREEN + "\n[*] Subnet Calculating:"+COLOR.WHITE)
    dns_url = f"http://api.hackertarget.com/subnetcalc/?q={target}"
    response = requests.get(dns_url)
    print(response.text)

# Vulnerability Scanning
def vulnerability_scanning():
    os.system('clear')
    banner()
    print(COLOR.PURPLE + "\n=== Vulnerability Scanner ==="+ COLOR.WHITE)
    target = input(COLOR.LIGHT_CYAN + "[?] Enter the target URL or IP: "+ COLOR.WHITE)
    print(COLOR.LIGHT_GREEN + "\n[+] Scanning for vulnerabilities...\n"+COLOR.WHITE)

    # Perform Vulnerability Scanning
    os.system('nikto -Tuning all -C all -h {}'.format(target))

# Web Crawling
def web_crawling():
    os.system('clear')
    banner()
    print(COLOR.PURPLE + "\n=== Web Crawling ==="+ COLOR.WHITE)
    target = input(COLOR.LIGHT_CYAN + "[?] Enter the target URL: "+ COLOR.WHITE)
    if not target.startswith('http'):
        target = 'http://' + target

    print(COLOR.LIGHT_GREEN + "\n[+] Crawling the website...\n"+COLOR.WHITE)

    # Send HTTP GET request and parse HTML
    response = requests.get(target)
    soup = BeautifulSoup(response.content, 'html.parser')

    # Extract and print all the links on the page
    print(COLOR.GREEN + "[*] Links found on the page:"+COLOR.WHITE)
    for link in soup.find_all('a'):
        print(link.get('href'))


# TLS / SSL Scan
def ssl_scan():
    os.system('clear')
    banner()
    print(COLOR.PURPLE + "\n=== TLS / SSL Scan ==="+ COLOR.WHITE)
    target = input(COLOR.LIGHT_CYAN + "[?] Enter the target URL: "+ COLOR.WHITE)
    print(COLOR.LIGHT_GREEN + "\n[+] Performing SSL Scan...\n"+COLOR.WHITE)
    os.system('sslyze {}'.format(target))    

# Basic Scan
def basic_scan():
    os.system('clear')
    banner()
    print(COLOR.PURPLE + "\n=== Basic Scan ==="+ COLOR.WHITE)
    target = input(COLOR.LIGHT_CYAN + "[?] Enter the target URL: "+ COLOR.WHITE)
    if not target.startswith('http'):
        target = 'http://' + target

    print(COLOR.LIGHT_GREEN + "\n[+] Performing Basic Scan...\n"+COLOR.WHITE)
    
    # Fetch site title
    response = requests.get(target)
    soup = BeautifulSoup(response.content, 'html.parser')
    title = soup.title.string if soup.title else 'N/A'
    print(COLOR.GREEN + f"[*] Site Title: {title}"+COLOR.WHITE)

    # Fetch IP address
    ip = socket.gethostbyname(urlparse(target).hostname)
    print(COLOR.GREEN + f"[*] IP Address: {ip}"+COLOR.WHITE)

    # Web server detection
    server_header = response.headers.get('Server')
    if server_header:
        print(COLOR.GREEN + f"[*] Web Server: {server_header}"+COLOR.WHITE)
    else:
        print(COLOR.RED + "[-] Web Server: N/A"+COLOR.WHITE)

    # CMS detection with builtwith
    technologies = builtwith.builtwith(target)
    cms = technologies.get('cms', [])
    if cms:
        cms_name = cms[0]
        print(COLOR.GREEN + f"[*] CMS: {cms_name}"+COLOR.WHITE)
    else:
        print(COLOR.RED + "[-] CMS: N/A"+COLOR.WHITE)

    # Cloudflare detection
    cloudflare_url = f"https://dnsdumpster.com/static/map/{target}.png"
    cloudflare_response = requests.get(cloudflare_url)
    if cloudflare_response.status_code == 200:
        print(COLOR.GREEN + "[*] Cloudflare: Detected"+COLOR.WHITE)
    else:
        print(COLOR.RED + "[-] Cloudflare: Not Detected"+COLOR.WHITE)

    # robots.txt scanner
    robots_url = target + "/robots.txt"
    response = requests.get(robots_url)
    if response.status_code == 200:
        print(COLOR.GREEN + f"\n[*] Robots.txt:\n{response.text}"+COLOR.WHITE)
    else:
        print(COLOR.RED + "\n[-] Robots.txt: N/A"+COLOR.WHITE)

    # sitemap.xml scanner
    sitemap_url = target + "/sitemap.xml"
    response = requests.get(sitemap_url)
    if response.status_code == 200:
        print(COLOR.GREEN + f"\n[*] Sitemap.xml:\n{response.text}"+COLOR.WHITE)
    else:
        print(COLOR.RED + "\n[-] Sitemap.xml: N/A"+ COLOR.WHITE)

# Network Scan
def nmap_scan(target, scan_options):
    print("[+] Running Nmap scan...\n")

    # Construct the Nmap command
    command = f"nmap {scan_options} {target}"

    # Execute the Nmap command
    scan_output = subprocess.check_output(command, shell=True, universal_newlines=True)
    print(scan_output)

# Banner Grabbing
def grab_banners():
    os.system('clear')
    banner()
    print(COLOR.PURPLE + "\n=== Banner Grabbing ==="+ COLOR.WHITE)
    target = input(COLOR.LIGHT_CYAN + "[?] Enter the target URL or IP: "+ COLOR.WHITE)
    print(COLOR.LIGHT_GREEN + "\n[+] Grabbing banners...\n"+COLOR.WHITE)

    try:
        ip = socket.gethostbyname(target)
        print(COLOR.GREEN + f"[*] IP Address: {ip}"+COLOR.WHITE)

        # Send HTTP GET request and get server header
        response = requests.get(f"http://{target}")
        server_header = response.headers.get('Server')
        if server_header:
            print(COLOR.GREEN + f"[*] Server: {server_header}"+COLOR.WHITE)
        else:
            print(COLOR.RED + "[!] Server header not found."+ COLOR.WHITE)
    except socket.gaierror:
        print(COLOR.RED + "[!] Invalid target URL or IP."+ COLOR.WHITE)

# Subdomain Finder
def find_subdomains():
    os.system('clear')
    banner()
    print(COLOR.PURPLE + "\n=== Subdomain FInder ==="+ COLOR.WHITE)
    target = input(COLOR.LIGHT_CYAN + "[?] Enter the target URL or IP: "+ COLOR.WHITE)
    protocol = input(COLOR.LIGHT_CYAN + "[?] Select the protocol: 1. HTTP 2. HTTPS: "+ COLOR.WHITE)
    protocol = "http" if protocol == "1" else "https"
    port = input(COLOR.LIGHT_CYAN + f"[?] Enter the port number for {protocol}: "+ COLOR.WHITE)
    wordlist = input(COLOR.LIGHT_CYAN + "[?] Please enter the web directory list/wordlist (leave empty for default): "+ COLOR.WHITE)
    if wordlist == "":
        wordlist = "payloads/big.txt"
    print(COLOR.LIGHT_GREEN + "\n[+] Subdomain Finding...\n"+COLOR.WHITE)
    command = f"ffuf -w {wordlist} -u {protocol}://FUZZ.{target}:{port} -fc 404"
    output = subprocess.check_output(command, shell=True, universal_newlines=True)
    print(output)

# Directory Lister
def find_directories():
    os.system('clear')
    banner()
    print(COLOR.PURPLE + "\n=== Directory Lister ==="+ COLOR.WHITE)
    target = input(COLOR.LIGHT_CYAN + "[?] Enter the target URL or IP: "+ COLOR.WHITE)
    protocol = input(COLOR.LIGHT_CYAN + "[?] Select the protocol: 1. HTTP 2. HTTPS: "+ COLOR.WHITE)
    protocol = "http" if protocol == "1" else "https"
    port = input(COLOR.LIGHT_CYAN + f"[?] Enter the port number for {protocol}: "+ COLOR.WHITE)
    wordlist = input(COLOR.LIGHT_CYAN + "[?] Please enter the web directory list/wordlist (leave empty for default): "+ COLOR.WHITE)
    if wordlist == "":
        wordlist = "payloads/big.txt"
    print(COLOR.LIGHT_GREEN + "\n[+] Directory Listing...\n"+COLOR.WHITE)
    command = f"ffuf -w {wordlist} -u {protocol}://{target}:{port}/FUZZ -fc 404"
    output = subprocess.check_output(command, shell=True, universal_newlines=True)
    print(output)


# WordPress Scan
def wordPress_scan():
    banner()
    print(COLOR.PURPLE + "\n=== Wordpress Scan ==="+ COLOR.WHITE)
    target = input(COLOR.LIGHT_CYAN + "[?] Enter the target URL or IP: "+ COLOR.WHITE)
    print(COLOR.LIGHT_GREEN + "\n[+] Wordpress Scanning...\n"+COLOR.WHITE)

    # Perform Wpscan
    os.system('wpscan --url {} --no-banner'.format(target))


# Joomla Scan
def joomla_scan():
    banner()
    print(COLOR.PURPLE + "\n=== Joomla Scan ==="+ COLOR.WHITE)
    target = input(COLOR.LIGHT_CYAN + "[?] Enter the target URL or IP: "+ COLOR.WHITE)
    print(COLOR.LIGHT_GREEN + "\n[+] Joomla Scanning...\n"+COLOR.WHITE)

    # Perform Joomla scan
    os.system('perl joomscan/joomscan.pl -ec -r --url {}'.format(target))


# Auto find CMS and Scan
def autocms_scan():
    banner()
    print(COLOR.PURPLE + "\n=== Auto Find CMS and Scan ==="+ COLOR.WHITE)
    target = input(COLOR.LIGHT_CYAN + "[?] Enter the target URL or IP: "+ COLOR.WHITE)
    print(COLOR.LIGHT_GREEN + "\n[+] CMS Detecting and Scanning...\n"+ COLOR.WHITE)

    # Perform Auto find CMS and Scan
    os.system('droopescan scan --enumerate a --url {}'.format(target))


# SQL Injection Finder
def sql_injection_finder():
    os.system('clear')
    banner()
    print(COLOR.PURPLE + "\n=== SQL Injection ==="+ COLOR.WHITE)
    target = input(COLOR.LIGHT_CYAN + "[?] Enter the target URL: "+ COLOR.WHITE)
    payload_list = input(COLOR.LIGHT_CYAN + "[?] Enter the path to the payload list (leave empty for default): "+ COLOR.WHITE)
    if payload_list == "":
        payload_list = "payloads/sqli-payloads.txt"

    print(COLOR.LIGHT_GREEN + "\n[+] SQL Injection Detection In Progress...\n"+ COLOR.WHITE)

    try:
        with open(payload_list, 'r') as file:
            payloads = file.readlines()

        vulnerable_payloads = []

        for payload in payloads:
            payload = payload.strip()

            # Create the URL with the payload
            url = f"{target}{payload}"

            try:
                response = requests.get(url)

                # Check if the response contains error messages indicating a SQL injection vulnerability
                if "error" in response.text.lower() or "sql syntax" in response.text.lower():
                    vulnerable_payloads.append(payload)

            except requests.exceptions.RequestException:
                print(COLOR.RED + f"[!] Error occurred while making a request to: {url}"+ COLOR.WHITE)

        if vulnerable_payloads:
            print(COLOR.GREEN + "[+] SQL injection vulnerability detected with the following payloads:"+ COLOR.WHITE)
            for payload in vulnerable_payloads:
                print(payload)

        else:
            print(COLOR.RED + "[-] No SQL injection vulnerability detected."+ COLOR.WHITE)

    except FileNotFoundError:
        print(COLOR.RED + "[!] Payload list file not found."+ COLOR.WHITE)


# XSS Finder
def xss_finder():
    os.system('clear')
    banner()
    print(COLOR.PURPLE + "\n=== XSS Finder ==="+ COLOR.WHITE)
    target = input(COLOR.LIGHT_CYAN + "[?] Enter the target URL: "+ COLOR.WHITE)
    payload_file = input(COLOR.LIGHT_CYAN + "[?] Enter the path to the payload list file (leave empty for default): "+ COLOR.WHITE)

    if not payload_file:
        payload_file = "payloads/xss-payload.txt"

    payloads = []
    with open(payload_file, "r") as file:
        payloads = file.read().splitlines()

    print(COLOR.LIGHT_GREEN + "\n[+] XSS Finding In Progress...\n"+ COLOR.WHITE)

    xss_vulnerabilities = []
    for payload in payloads:
        # Construct the payload URL
        payload_url = f"{target}{payload}"

        # Send request with payload
        response = requests.get(payload_url)

        # Check if payload is reflected in the response
        if payload in response.text:
            xss_vulnerabilities.append(payload)

    if xss_vulnerabilities:
        print(COLOR.GREEN + "[+] XSS vulnerabilities found with payloads:"+ COLOR.WHITE)
        for payload in xss_vulnerabilities:
            print(payload)
            #input("Press Enter to continue...")
            
    else:
        print(COLOR.RED + "[-] No XSS vulnerabilities detected."+ COLOR.WHITE)
        #input("Press Enter to continue...")

# LFI Vulnerability Finder
def lfi_vulnerability_finder():
    os.system('clear')
    banner()
    print(COLOR.PURPLE + "\n=== LFI Finder ==="+ COLOR.WHITE)
    target = input(COLOR.LIGHT_CYAN + "[?] Enter the target URL: "+ COLOR.WHITE)
    payload_file = input(COLOR.LIGHT_CYAN + "[?] Enter the path to the payload list file (leave empty for default): "+ COLOR.WHITE)

    if not payload_file:
        # Use default payloads if no file is provided
        payload_file = "payloads/lfi-payloads.txt"
        print(COLOR.GREEN + "[+] Using default payload list: lfi-payloads.txt"+ COLOR.WHITE)

    try:
        with open(payload_file, "r") as file:
            payloads = file.read().splitlines()
    except FileNotFoundError:
        print(COLOR.RED + f"[!] File not found: {payload_file}"+ COLOR.WHITE)
        return

    print(COLOR.LIGHT_GREEN + "\n[+] Searching for LFI vulnerabilities...\n"+ COLOR.WHITE)

    # Send requests with LFI payloads
    for payload in payloads:
        url = f"{target}{payload}"
        response = requests.get(url)
        if response.status_code == 200:
            print(COLOR.GREEN + f"[+] Vulnerable URL: {url}"+ COLOR.WHITE)

# S3 Bucket Scanner
def s3scaner_bucket():
    os.system('clear')
    banner()
    print(COLOR.YELLOW + "\n[!] S3 Bucket Scanner Tool Coming Soon...Stay Tuned.😉"+ COLOR.WHITE)

# Smart Contracts Analyze
def smart_contract():
    os.system('clear')
    banner()
    print(COLOR.YELLOW + "\n[!] Smart Contracts Analysis Tool Coming Soon...Stay Tuned.😉"+ COLOR.WHITE)

# Read Brahmastra
def read():
    os.system('clear')
    banner()
    with open("assets/txt/read.txt", "r") as file:
        contents = file.read()
        print(contents)
        input("\nPress Enter to continue...")
        brahmastra()

# Video Brahmastra
def play_video():
    # Path to the video file
    video_path = "assets/video/brahmastra.mp4"
    if os.name == "posix":  # Linux or Mac
        if os.uname().sysname == "Darwin":  # Mac
            os.system(f'open "{video_path}"')
        else:  # Linux
            os.system(f'xdg-open "{video_path}"')
    elif os.name == "nt":  # Windows
        os.system(f'start "{video_path}"')
    
    os.system('clear')
    banner()
    input("\nPress Enter to continue...")
    brahmastra()

    # Call the function to play the video
    play_video()


# About Brahmastra
def brahmastra():
    os.system('clear')
    banner()
    print(COLOR.PINK + STYLE.BOLD + "\n=== About Brahmastra ===" +COLOR.WHITE + COLOR.WHITE)
    print("""+--------------------------------------------------------------+                                                  
+                  List Of Actions                    +                                                  
+--------------------------------------------------------------+""")
    print("1. Read About Brahmastra:")
    print("2. Video About Brahmastra:")
    print("B. Back to Main Menu")
    print("0. Exit")
    about_choice = input(COLOR.LIGHT_CYAN + "\n[$] Enter your choice: "+ COLOR.WHITE)  

    if about_choice == '1':
        read()
    elif about_choice == '2':
        play_video()
    elif about_choice == 'B':
        menu()
    elif about_choice == 'b':
        menu()
    elif about_choice == '0':
        print("\n[?] Are you sure you want to exit the program? [y/n]: ")
        while True:
            user_input = input().lower()
            if user_input == "y":
                os.system('clear')
                banner()
                print(COLOR.YELLOW + "\n \n [^] Exiting the program...Goodbye! 👋"+ COLOR.WHITE)
                exit()
                sys.exit(0)
            elif user_input == "n":
                #print("Resuming program execution.")
                brahmastra()
            else:
                print(COLOR.RED + "[-] Invalid input. Please enter 'y' or 'n'."+ COLOR.WHITE)

    else:
        print(COLOR.RED + "[-] Invalid choice. Please try again."+ COLOR.WHITE)
        input("Press Enter to continue...")
        os.system('clear')
        brahmastra()


# Sub Menu
def menu_two():
    os.system('clear')
    banner()
    print(COLOR.PINK + STYLE.BOLD + "\n=== CMS Find and Scan ===" +COLOR.WHITE + COLOR.WHITE)
    print("""+--------------------------------------------------------------+                                                  
+                  List Of Scans Or Actions                    +                                                  
+--------------------------------------------------------------+""")
    print("1. WordPress Scan:")
    print("2. Joomla Scan:")
    print("3. Auto find CMS and Scan:")
    print("B. Back to Main Menu")
    print("0. Exit")
    sub_choice = input(COLOR.LIGHT_CYAN + "\n[$] Enter your choice: "+ COLOR.WHITE)

    if sub_choice == '1':
        os.system('clear')
        wordPress_scan()
    elif sub_choice == '2':
        os.system('clear')
        joomla_scan()
    elif sub_choice == '3':
        os.system('clear')
        autocms_scan()
    elif sub_choice == 'B':
        menu()
    elif sub_choice == 'b':
        menu()
    elif sub_choice == '0':
        print("\n[?] Are you sure you want to exit the program? [y/n]: ")
        while True:
            user_input = input().lower()
            if user_input == "y":
                os.system('clear')
                banner()
                print(COLOR.YELLOW + "\n \n [^] Exiting the program...Goodbye! 👋"+ COLOR.WHITE)
                exit()
                sys.exit(0)
            elif user_input == "n":
                #print("Resuming program execution.")
                menu_two()
            else:
                print(COLOR.RED + "[-] Invalid input. Please enter 'y' or 'n'."+ COLOR.WHITE)
    else:
        print(COLOR.RED + "[-] Invalid choice. Please try again."+ COLOR.WHITE)
        input("Press Enter to continue...")
        os.system('clear')
        menu_two()

# Main Menu
def menu():
    while True:
        input("Press Enter to continue...")
        os.system('clear')
        banner()
        print(COLOR.PINK + STYLE.BOLD + "\n-------- Ultimate Security Scanner ToolKit --------\n" + COLOR.WHITE + COLOR.WHITE)
        print("""+--------------------------------------------------------------+                                                  
+                  List Of Scans Or Actions                    +                                                  
+--------------------------------------------------------------+""")
        print("0. OSINT Analysis:")
        print("1. Gather Information:")
        print("2. Vulnerability Scanning:")
        print("3. Web Crawling:")
        print("4. TLS / SSL Scan:")
        print("5. Basic Scan:")
        print("6. Banner Grabbing:")
        print("7. Subdomain Finder:")
        print("8. Directory Lister:")
        print("9. CMS Find and Scan:")
        print("10. Network Scan:")
        print("11. SQL Injection Finder:")
        print("12. XSS Finder:")
        print("13. LFI Finder:")
        print("14. S3 Bucket Scanner:")
        print("15. Smart Contracts Analysis:")
        print("A. About Brahmastra")
        print("99. Exit")
        choice = input(COLOR.LIGHT_CYAN + "\n[$] Enter your choice: "+ COLOR.WHITE)

        if choice == '0':
            find_social_media_profiles()

        elif choice == '1':
            gather_information()
        
        elif choice == '2':
            vulnerability_scanning()
        
        elif choice == '3':
            web_crawling()

        elif choice == '4':
            ssl_scan()
        
        elif choice == '5':
            basic_scan()
        
        elif choice == '6':
            grab_banners()
        
        elif choice == '7':
            find_subdomains()
        
        elif choice == '8':
            find_directories()
        
        elif choice == '9':
            menu_two()
        
        elif choice == '10':
            os.system('clear')
            banner()
            print(COLOR.PURPLE + "\n=== Network Scanner ==="+ COLOR.WHITE)
            target = input(COLOR.LIGHT_CYAN + "[?] Enter the target URL or IP: "+ COLOR.WHITE)
            scan_options = input(COLOR.LIGHT_CYAN + "[?] Enter Nmap scan options (leave empty for default): "+ COLOR.WHITE)
            if scan_options == "":
                scan_options = "-sC -sV -Pn -p1-1000 -A"
            nmap_scan(target, scan_options)

        elif choice == '11':
            sql_injection_finder()
        
        elif choice == '12':
            xss_finder()
        
        elif choice == '13':
            lfi_vulnerability_finder()
        
        elif choice == '14':
            s3scaner_bucket()
        
        elif choice == '15':
            smart_contract()
        elif choice == 'A':
            brahmastra()
        elif choice == 'a':
            brahmastra()
        elif choice == '99':
            print("\n[?] Are you sure you want to exit the program? [y/n]: ")
            while True:
                user_input = input().lower()
                if user_input == "y":
                    os.system('clear')
                    banner()
                    print(COLOR.YELLOW + "\n \n [^] Exiting the program...Goodbye! 👋"+ COLOR.WHITE)
                    exit()
                    #sys.exit(0)
                elif user_input == "n":
                    menu()
                else:
                    print(COLOR.RED + "[-] Invalid input. Please enter 'y' or 'n'."+ COLOR.WHITE)
        else:
            print(COLOR.RED + "[-] Invalid choice. Please try again."+ COLOR.WHITE)
            #input("Press Enter to continue...")

# Run the main menu
while True:
    if menu():
        break
