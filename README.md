## ℹ️ Brahmastra:

"Brahmastra" is a powerful security analysis tool inspired by the ancient Indian mythology of Lord Brahma. Just as Lord Brahma was known for his divine wisdom and knowledge, this tool embodies those qualities by offering a comprehensive range of security assessment functionalities. With its Python-based script, Brahmastra combines network scanning, web crawling, vulnerability scanning, and CMS detection capabilities. By utilizing external tools and modules, it enables users to discover social media profiles, gather information, perform SSL analysis, identify subdomains, detect vulnerabilities such as SQL injection and XSS, and much more. The tool's intuitive menu system provides an easy-to-use interface, empowering security professionals to conduct thorough security assessments and uncover potential vulnerabilities and weaknesses in target systems. Embracing the name of an ancient divine weapon, Brahmastra aims to provide security practitioners with a potent tool to safeguard modern digital environments.


![alt text](https://github.com/Debajyoti0-0/Brahmastra/blob/main/assets/img/Brahmastra.png)



## 🛠️ Installation:

* Simply execute the following command

```bash
git clone https://github.com/Debajyoti0-0/Brahmastra.git
```

* Use the package manager [pip](https://pip.pypa.io/en/stable/) to install Python libraries requirements.

```bash
sudo apt install python3-pip -y
```

```bash
cd Brahmastra
chmod +x *
sudo pip3 install -r requirements.txt
```

* Then install the other requirements.

```bash
sudo ./install_tools.sh
```

## 🎯 Features:


- OSINT Analysis: The tool allows you to find social media profiles associated with a target username. It utilizes the "social-analyzer" tool for this purpose.

- Information Gathering: You can gather various types of information about a target URL or IP. It performs WHOIS lookup, DNS lookup, GEOIP lookup, and subnet calculation to provide detailed information about the target.

- Vulnerability Scanning: The tool supports vulnerability scanning using the Nikto tool. It scans the target URL or IP for common vulnerabilities and provides detailed output.

- Web Crawling: You can crawl a website by providing the target URL. The tool sends an HTTP GET request, parses the HTML content, and extracts and displays all the links found on the page.

- TLS/SSL Scan: It allows you to perform an SSL scan on a target URL. The tool uses "sslyze" for this purpose and provides information about the SSL configuration of the target.

- Basic Scan: This feature performs a basic scan on a target URL. It fetches the site title, IP address, web server information, CMS detection using "builtwith," Cloudflare detection, and scans for robots.txt and sitemap.xml files.

- Network Scan: The tool supports Nmap scanning by allowing you to specify the target and scan options. It executes the Nmap command and displays the scan output.

- Banner Grabbing: It can grab banners from a target URL or IP. The tool retrieves the IP address and sends an HTTP GET request to get the server header.

- Subdomain Finder: This feature helps in finding subdomains of a target URL or IP. It uses the "ffuf" tool with a wordlist to perform the subdomain enumeration.

- Directory Lister: It allows you to find directories on a target URL or IP. The tool uses "ffuf" with a wordlist to perform directory enumeration.

- CMS Specific Scans: The tool includes specific scans for popular CMS platforms like WordPress and Joomla. It utilizes "wpscan" for WordPress scanning and "joomscan" for Joomla scanning.

- SQL Injection Finder: It performs SQL injection detection on a target URL. You can provide a payload list, and the tool sends requests with each payload to check for vulnerability.

- XSS Finder: This feature helps in detecting XSS vulnerabilities on a target URL. You can provide a payload list, and the tool sends requests with each payload to check for reflected XSS.

- LFI Vulnerability Finder: The tool assists in finding Local File Inclusion (LFI) vulnerabilities on a target URL. It checks if the target URL is susceptible to LFI attacks.

These are the main features of the Brahmastra tool, offering a range of functionalities for reconnaissance, vulnerability assessment, and security testing.


## ⁉️ Usage:

```bash
python3 Brahmastra.py
```

## 📸 Screenshot:

![alt text](https://github.com/Debajyoti0-0/Brahmastra/blob/main/assets/img/Screenshot.png)


## 💚 Contributing:

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.



## 🔑 License:

Distributed under the GNU V3.0 License. See [LICENSE](https://github.com/Debajyoti0-0/Brahmastra/blob/main/LICENSE) for more information.

-----
Project Maintainer: [Debajyoti Haldar](https://github.com/Debajyoti0-0/) 



[<img src="https://img.icons8.com/color/48/000000/instagram-new.png"/>](https://instagram.com/debajyoti0_0) [<img src="https://img.icons8.com/color/48/000000/twitter--v2.png"/>](https://twitter.com/Debajyoti077) [<img src="https://img.icons8.com/color/48/000000/domain.png"/>](https://dailycyberinfo1.blogspot.com/) [<img src="https://img.icons8.com/color/48/000000/linkedin.png"/>](https://www.linkedin.com/in/debajyoti-haldar-86ba62153/) [<img src="https://img.icons8.com/color/48/000000/facebook.png"/>](https://www.facebook.com/debajyoti.h)
<img src="http://www.hackthebox.eu/badge/image/718010" alt="Hack The Box">
