# http-server
A lightweight, multi-threaded HTTP server built from scratch using C and POSIX sockets. Designed with security and performance in mind, demonstrating low-level network programming and secure coding practices.

# Overview
This project implements a functional HTTP/1.1 server without relying on external web server libraries. Each client connection is handled in a separate thread, allowing concurrent request processing. The server includes security features like request validation, rate limiting, and comprehensive logging.

# Why I Built This:
To understand how web servers work at the lowest level and to practice writing secure, production-quality C code. This project bridges my development skills with security awareness - essential for application security roles.

# Features:

  # Multi-threaded Architecture: 
    Each connection handled by dedicated thread using POSIX threads
  # HTTP/1.1 Support: 
    GET and POST method handling with proper response codes
  # Security-Focused:
    Input validation to prevent buffer overflows
    Rate limiting to prevent abuse (configurable requests per IP)
    Request size limits to prevent DoS
    Sanitized error messages (no internal info leakage)
  # Comprehensive Logging: 
    All requests, errors, and suspicious activity logged with timestamps
  # Static File Serving: 
    Serves HTML, CSS, JS, images with correct MIME types
  # Graceful Error Handling: 
    Proper HTTP error responses (400, 404, 500, etc.)

# Technical Details
Built With:
  C (C99 standard)
  POSIX sockets API
  POSIX threads (pthread)
  Standard C libraries only
