# InjecTalon
A powerful, extensible, and automated SQL Injection reconnaissance tool built for bug bounty hunters and red teams.
# InjectaScan v1.0

**Unified SQL Injection Testing Toolkit**  
Author: Hammad Munir  
Company: 6amsolution Private Limited  

---

## Introduction

InjectaScan is a modular Python tool designed to streamline and automate SQL Injection testing by integrating and orchestrating some of the most popular and effective SQLi tools available. Whether you prefer command-line scanners like sqlmap or want to leverage GUI and manual tools, InjectaScan helps centralize your workflow.

---

## Supported Tools

| Tool         | Description                                                   | Notes                                  |
|--------------|---------------------------------------------------------------|----------------------------------------|
| **sqlmap**   | Industry-standard automated SQL Injection and takeover tool   | Fully automated CLI scanner            |
| **Commix**   | Automated command and SQL injection exploitation tool         | Python-based CLI tool                   |
| **SQLNinja** | Focused on MSSQL injection exploitation                       | Requires manual use                     |
| **NoSQLMap** | Tests NoSQL databases for injection flaws                    | Automated CLI scanner                   |
| **OWASP ZAP**| Open-source GUI and headless scanner with SQLi detection      | Manual/GUI; API automation possible    |
| **Nikto**    | Web server scanner detecting SQLi among other vulnerabilities | CLI tool                              |
| **Wfuzz**    | Web app brute-forcer supporting injection testing             | Requires custom payloads & wordlists   |

---

## Installation

### Prerequisites

- Python 3.7+ installed
- Relevant tools installed on your system (e.g., sqlmap, commix, nikto)
- Linux/Mac recommended for full functionality; Windows with WSL can work

### Install tools (examples)

```bash
# Install sqlmap
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
export PATH=$PATH:$(pwd)/sqlmap-dev

# Install commix
git clone --depth 1 https://github.com/commixproject/commix.git commix-dev
export PATH=$PATH:$(pwd)/commix-dev

# Install nikto
sudo apt-get install nikto
