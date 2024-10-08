# VulnSec 🛡️

### **Advanced Web Vulnerability Scanner**

VulnSec is a Python-based web vulnerability scanning tool designed to help security professionals identify and mitigate potential vulnerabilities in websites and network services. It leverages powerful tools like Nmap for port scanning and HTTP request libraries to check for security headers and potential SQL injection risks. 

With an intuitive command-line interface, VulnSec allows users to quickly assess a target's security posture by specifying different testing options. **This tool is intended for ethical hacking and security auditing purposes only.** 

---
## **Features**

- **Port Scanning**: Quickly scan a range of common ports and detect open ones.
- **HTTP Header Analysis**: Check for missing or insecure HTTP security headers.
- **SQL Injection Testing**: Identify possible SQL injection vulnerabilities in web applications.
- **General Vulnerability Scanning**: Use Nmap scripts to check for a wide range of common vulnerabilities.

---

## **Installation**

To install **VulnSec**, ensure you have the following prerequisites:

### **Prerequisites:**

- **Kali Linux** (or any Linux distribution with Python3 and Nmap installed)
- **Python3** 
- **Nmap**
- **pip** (Python package manager)

### **Steps:**

1. Clone the GitHub repository:

    ```bash
    git clone https://github.com/Karimselmi/vulnsec.git
    ```

2. Navigate into the project directory:

    ```bash
    cd vulnsec
    ```

3. Install the necessary Python dependencies:

    ```bash
    pip install -r requirements.txt
    ```

---

## **Usage**

After installation, run **VulnSec** from the terminal with the following command:

```bash
python3 vulnsec.py [OPTION] [TARGET_URL]
```

### **Options:**

- `-v` : Perform a vulnerability scan using Nmap.
- `-p` : Perform port scanning (quick scan on common ports).
- `-H` : Check HTTP headers for missing security configurations.
- `-S` : Test for SQL Injection vulnerabilities.

### **Example Usage:**

1. **Port Scanning**:

    ```bash
    VulnSec: -p https://example.com
    ```

2. **HTTP Header Check**:

    ```bash
    VulnSec: -H https://example.com
    ```

3. **SQL Injection Testing**:

    ```bash
    VulnSec: -S https://example.com/login
    ```

4. **Vulnerability Scan**:

    ```bash
    VulnSec: -v https://example.com
    ```

---

## **ScreenShot**

```bash
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
    
    

     VulnSec  is a Python-based vulnerability scanner designed to help identify potential security risks in websites. 
    It allows scanning for open ports, SQL injection vulnerabilities, HTTP header security, and general vulnerabilities using Nmap.
    

    Usage: 
    VulnSec [OPTION] [TARGET_URL]

    Options:
    -v  Perform vulnerability scan
    -p  Perform port scanning (quick scan)
    -H  Check HTTP headers
    -S  Test for SQL Injection

    Example:
    VulnSec: -p https://example.com
    
VulnSec:
```

---

## **Warning** ⚠️

**VulnSec** is intended strictly for **ethical hacking**, **legal penetration testing**, and **security research** purposes. Any unauthorized use of this tool to exploit websites or systems without the owner's permission is illegal and may lead to severe consequences.

- Always ensure that you have **written authorization** before scanning any systems.
- The developers of **VulnSec** are not responsible for any misuse of the tool.

---

## **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
