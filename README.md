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

### Coming Soon
- 🚧 TLS 1.2/1.3 encryption
- 🚧 Security testing tools (scanner, fuzzer, analyzer)
- 🚧 Vulnerability documentation
- 🚧 Comprehensive security analysis

## 🚀 Quick Start

### Prerequisites
- GCC compiler
- Make (optional but recommended)

### Build and Run

```bash
# Clone the repository
git clone https://github.com/yourusername/http-tls-security-toolkit.git
cd http-tls-security-toolkit

# Compile
gcc -o server src/server.c -Wall -Wextra

# Run server
./server

# Test in another terminal
curl http://localhost:8080/
```

### Test POST Requests

```bash
curl -X POST http://localhost:8080/submit \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=Test&email=test@example.com"
```

## 📁 Project Structure

```
http-tls-security-toolkit/
├── src/              # Server source code
│   └── server.c      # Main HTTP server implementation
├── www/              # Static web files
│   ├── index.html
│   ├── about.html
│   └── submit.html
└── README.md
```

## 🛠️ Technologies

- **Language:** C
- **Network:** POSIX sockets
- **Upcoming:** OpenSSL for TLS, Python for security tools

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
