# HTTP/TLS Server & Security Testing Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Language: C](https://img.shields.io/badge/Language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Status: In Development](https://img.shields.io/badge/Status-In%20Development-orange.svg)]()

A lightweight HTTP/TLS server built from scratch in C to deeply understand network security, cryptographic protocols, and common web vulnerabilities.

## 🎯 Project Goals

This project demonstrates:
- Low-level network programming with sockets
- HTTP/1.1 protocol implementation
- TLS/SSL encryption with OpenSSL
- Security vulnerability research and documentation
- Building security testing tools from scratch

## ✨ Features

### Currently Implemented
- ✅ HTTP/1.1 server with socket programming
- ✅ GET request handling for static files
- ✅ POST request handling with form data
- ✅ Multiple route support
- ✅ Proper HTTP status codes (200, 404, 400, 405, 500)
- ✅ TLS 1.2/1.3 encryption
- ✅ Multi-connection support with process forking
- ✅ TLS Scanner (cipher suites, certificate validation, protocol version testing)

### Coming Soon
- 🚧 More security testing tools (fuzzer, traffic analyzer)
- 🚧 Vulnerability documentation
- 🚧 Comprehensive security analysis

## 🚀 Quick Start

### Prerequisites
- GCC compiler
- OpenSSL development libraries
- Python 3 (for security tools)
- Make (recommended)

### Build and Run

```bash
# Clone the repository
git clone https://github.com/EthanMartin123/http-tls-security-toolkit.git
cd http-tls-security-toolkit

# Create Certificates & Compile
make setup 

# Run this if you need help!
make help

# Run server
./server

# Test in your browser!
https://localhost:8080/
```

### Security Testing

```bash
# Run TLS vulnerability scanner
python3 tools/tls-scanner.py localhost 8080

# Check certificate expiration, signature algorithm, and key size
# Test for weak ciphers and deprecated TLS versions
```

## 📁 Project Structure

```
http-server/                                                                             
├── src/                        # Server source code                                     
│   └── server.c                # Main HTTPS server implementation with TLS 1.3          
│                                                                                        
├── certs/                      # SSL/TLS certificates                                   
│   ├── generate_certs.sh       # Certificate generation script                          
│   ├── cert.pem                # Self-signed SSL certificate (auto-generated)           
│   └── key.pem                 # Private RSA key (auto-generated)                       
│                                                                                        
├── www/                        # Static web content                                     
│   ├── index.html              # Landing page                                           
│   ├── submit.html             # Secure form submission                                 
│   └── success.html            # Success confirmation                                   
│                                                                                        
├── tools/                      # Security testing utilities                             
│   └── tls-scanner.py          # TLS vulnerability scanner (certificate, cipher, protocol checks)
│                                                                                        
├── Makefile                    # Build automation (make, make run, make certs)          
├── .gitignore                  # Git ignore rules                                       
└── README.md                   # Project documentation
```

### Key Files

| File | Description | Lines |
|------|-------------|-------|
| `src/server.c` | Core HTTPS server with TLS implementation | 400+ |
| `tools/tls-scanner.py` | Security scanner for TLS vulnerabilities | 150+ |
| `certs/generate_certs.sh` | Automated SSL certificate generation | 20 |
| `www/*.html` | Modern, responsive web interface | 300+ |
| `Makefile` | Build system with multiple targets | 60 |

### Generated Files (gitignored)

- `server` - Compiled binary executable
- `certs/cert.pem` - SSL certificate (4096-bit RSA)
- `certs/key.pem` - Private key
- `output.txt` - Form submission data

## 🛠️ Technologies

- **Language:** C, Python
- **Network:** POSIX sockets, TCP/IP
- **Encryption:** OpenSSL for TLS 1.2/1.3
- **Security Tools:** Custom vulnerability scanners

## 🔒 Security Features

### Server Security
- TLS 1.2 and 1.3 support
- Strong cipher suites (AES-GCM, ChaCha20-Poly1305)
- 4096-bit RSA keys
- Process isolation with fork()

### Testing Tools
- Certificate validation (expiration, signature algorithm, key size)
- Weak cipher detection
- Deprecated protocol version testing
- Comprehensive vulnerability reporting

## 📚 Learning Journey

I'm documenting the entire build process through a blog series. Follow along to see challenges, solutions, and lessons learned.

- **Blog:** https://dev.to/ethan_ac5ca38abc559d950c9
- **Demo Video:** [Coming soon]

## 🎓 About This Project

This is part of my cybersecurity portfolio as I work toward an entry-level SOC analyst position. I'm building hands-on projects to demonstrate real-world security skills.

**Author:** Ethan Martin  
**University:** California State University, Channel Islands  
**Major:** Information Technology  
**Club:** Treasurer, Ethical Hackers of Channel Islands

## 📝 License

MIT License - see LICENSE file for details

## 🤝 Contributing

This is a personal learning project, but feedback and suggestions are welcome! Feel free to open an issue.

---

⭐ **Star this repo if you find it useful or interesting!**
