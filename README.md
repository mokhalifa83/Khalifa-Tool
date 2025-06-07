# 🔴 KHALIFA - Professional Web Security Scanner

<div align="center">

```
██   ██ ██   ██  █████  ██      ██ ███████  █████  
██  ██  ██   ██ ██   ██ ██      ██ ██      ██   ██ 
█████   ███████ ███████ ██      ██ █████   ███████ 
██  ██  ██   ██ ██   ██ ██      ██ ██      ██   ██ 
██   ██ ██   ██ ██   ██ ███████ ██ ██      ██   ██ 
```

**Professional Web Security Scanner & Penetration Testing Toolkit**

*Developed by Mohamed Khalifa*

[![Version](https://img.shields.io/badge/Version-2.0.1-brightgreen.svg)]()
[![Build](https://img.shields.io/badge/Build-KH--2024--7891--ALPHA-blue.svg)]()
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)]()
[![Python](https://img.shields.io/badge/Python-3.6+-red.svg)]()

</div>

## ⚡ Overview

**KHALIFA** is a comprehensive web security scanner designed for cybersecurity professionals, penetration testers, and security researchers. This powerful toolkit combines multiple security assessment modules into a single, easy-to-use interface.

## 🛡️ Features

### 🔍 **Port Scanner & Service Detection**
- Advanced TCP port scanning with service fingerprinting
- Multi-threaded scanning for optimal performance
- Service version detection and banner grabbing

### 📁 **Directory & File Brute Force**
- Comprehensive directory enumeration
- Custom wordlist support
- Hidden file and folder discovery
- Response code analysis

### 🔐 **SSL/TLS Security Analysis**
- Certificate validation and analysis
- Cipher suite enumeration
- Protocol version testing
- Vulnerability assessment for SSL/TLS implementations

### 🌐 **HTTP Header Security Scan**
- Security header analysis
- Missing security headers detection
- Configuration recommendations
- OWASP compliance checking

### 🕷️ **Web Crawler & Link Discovery**
- Intelligent web crawling
- Link extraction and analysis
- Sitemap generation
- Dead link detection

### ⚡ **Vulnerability Assessment**
- Common web vulnerability detection
- OWASP Top 10 scanning
- Custom payload injection
- Automated exploit detection

## 🚀 Installation

### Prerequisites
- Python 3.6 or higher
- pip package manager

### Quick Install
```bash
git clone https://github.com/mokhalifa83/Khalifa-Tool.git
cd Khalifa-Tool
pip install -r requirements.txt
python khalifa.py
```

### Termux Installation
```bash
pkg update && pkg upgrade
pkg install python git
git clone https://github.com/mokhalifa83/Khalifa-Tool.git
cd Khalifa-Tool
pip install -r requirements.txt
python khalifa.py
```

## 💻 Usage

### Basic Usage
```bash
python khalifa.py
```

### Command Line Options
The tool features an interactive menu system that guides you through each security assessment module.

1. **Port Scanner & Service Detection** - Scan target ports and identify running services
2. **Directory & File Brute Force** - Enumerate directories and files
3. **SSL/TLS Security Analysis** - Analyze SSL/TLS configuration
4. **HTTP Header Security Scan** - Check security headers
5. **Web Crawler & Link Discovery** - Crawl and map website structure
6. **Vulnerability Assessment** - Comprehensive security assessment

## 🎯 Target Configuration

Simply enter your target URL or IP address when prompted:
```
Target: http://example.com
Target: https://192.168.1.100
Target: http://subdomain.example.com:8080
```

## ⚠️ Legal Disclaimer

```
⚠️  WARNING: Use only on systems you own or have explicit permission to test
```

This tool is designed for:
- ✅ Authorized penetration testing
- ✅ Security research on owned systems
- ✅ Educational purposes in controlled environments
- ✅ Bug bounty programs with proper authorization

**KHALIFA** is intended for legitimate security testing only. Users are responsible for complying with all applicable laws and regulations. Unauthorized testing of systems you don't own is illegal and unethical.

## 📋 Requirements

- Python 3.6+
- requests
- socket
- threading
- ssl
- urllib
- beautifulsoup4
- colorama

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest new features.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Mohamed Khalifa**
- GitHub: [@mokhalifa83](https://github.com/mokhalifa83)
- Tool Version: 2.0.1
- Build: KH-2024-7891-ALPHA

## 🌟 Support

If you find this tool useful, please consider:
- ⭐ Starring the repository
- 🐛 Reporting bugs and issues
- 💡 Suggesting new features
- 🤝 Contributing to the codebase

---

<div align="center">

**Made with ❤️ for the cybersecurity community**

*Stay secure, stay vigilant* 🛡️

</div>
