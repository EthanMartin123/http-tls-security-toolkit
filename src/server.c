

// ========================================
// HTTP SERVER WITH TLS SUPPORT
// Author: Ethan Martin
// Purpose: Learning network security
// ========================================

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#define PORT "8080"
#define BACKLOG 1
#define BUFFER_SIZE 8192

SSL_CTX *setup_tls() {
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
  if (!ctx) {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_set_cipher_list(ctx, "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:AES128-SHA") == -1) {
    fprintf(stderr, "failed to set cipher list\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256")  == -1) {
    fprintf(stderr, "Failed to set TLS 1.3 cipher suites");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_use_certificate_file(ctx, "certs/cert.pem", SSL_FILETYPE_PEM) == -1) {
    perror("Unable to use cert file");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, "certs/key.pem", SSL_FILETYPE_PEM) == -1) {
    perror("Unable to use private key file");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_check_private_key(ctx) == -1) {
    fprintf(stderr, "Private Key does not match certificate\n");
    exit(EXIT_FAILURE);
  }

  printf("✅ TLS Configured Successfully\n");

  return ctx;
}

// ========================================
// FILE RESPONSE HANDLER
// Serves static files over HTTP
// Returns 404 if file not found
// ========================================

void send_file_response(SSL *ssl, const char* filepath) {
  FILE *file = fopen(filepath, "r");

  if (file == NULL) {
    const char* response_404 = 
      "HTTP/1.1 404 Not Found\r\n"
      "Content-Type: text/html\r\n"
      "\r\n"
      "<html><body><h1>404 Not Found</h1><p>The file does not exit</p></body></html>";
    

    SSL_write(ssl, response_404, strlen(response_404));
    printf("404 - File not found: %s\n", filepath);
    return;
  }

  fseek(file, 0, SEEK_END);
  long size = ftell(file);
  fseek(file, 0, SEEK_SET);

  char *file_content = malloc(size + 1);
  if (file_content == NULL) {
    fclose(file);
    const char* response_500 = 
      "HTTP/1.1 500 Internal Server Error"
      "Content-Type: text/html\r\n"
      "\r\n"
      "<html><body><h1>500 Internal Server Error</h1></body></html>";
    

    SSL_write(ssl, response_500, strlen(response_500));
    printf("500 - Internal Server Error\n");
    return;
  }

  fread(file_content, 1, size, file);
  file_content[size] = '\0';
  fclose(file);

  char response[BUFFER_SIZE];
  int header_len = snprintf(response, BUFFER_SIZE,
                            "HTTP/1.1 200 OK\r\n"
                            "Content-Type: text/html; charset=UTF-8\r\n"
                            "Content-Length: %ld\r\n"
                            "\r\n",
                            size);

  // send header 
  SSL_write(ssl, response, header_len);

  // send file content 
  SSL_write(ssl, file_content, size);

  printf("200 OK - Sent file: %s (%ld bytes)\n", filepath, size);
  free(file_content);
                          
}


// ========================================
// CONTENT-LENGTH EXTRACTION
// Parses HTTP headers for Content-Length
// Returns -1 if invalid/missing
// ========================================
int extract_content_length(SSL *ssl, const char* buffer) {
  
  const char* response_400 = 
    "HTTP/1.1 400 Bad Request\r\n"
    "Content-Type: text/html\r\n"
    "\r\n"
    "<html><body><h1>400 Bad Request</h1>"
    "<p>Missing or Invalid Content-Length Header</p></body></html>";
  

  char* result = strstr(buffer, "Content-Length:");
  if (result == NULL) {
    SSL_write(ssl, response_400, strlen(response_400));
    printf("400 Bad Request: Missing Content-Length\n");
    return -1;
  }
  

  // jump to the end of "Content-Length: ", extract decimal integer, store in content_length
  int content_length;
  if (sscanf(result + 15, "%d", &content_length) != 1) {
    SSL_write(ssl, response_400, strlen(response_400));
    printf("400 Bad Request: Invalid Content-Length\n");
    return -1;
  }

  return content_length;

}




// ========================================
// POST DATA PARSER
// Parses form data (key=value pairs)
// Writes to output.txt
// ========================================
void post_parse_data(char* full_body) {
  printf("DEBUG: Inside post_parse_data, full_body = [%s]\n", full_body);

  char filepath[512];
  strcpy(filepath, "output.txt");
  FILE *file = fopen(filepath, "a");
  if (file == NULL) {
    perror("Failed to open output file");
    return;
  }

  printf("DEBUG: File opened successfully\n");

  char *pair = strtok(full_body, "&");

  printf("DEBUG: First pair = [%s]\n", pair);

  while (pair != NULL) {

    printf("DEBUG: Processing pair = [%s]\n", pair);


    char *equals = strchr(pair, '=');
    printf("DEBUG: equals pointer = %p\n", (void*)equals);

    if (equals != NULL) {
      *equals = '\0';
      char *key = pair;
      char *value = equals + 1;

      fprintf(file, "%s: %s\n", key, value);
      printf("DEBUG: Wrote to file\n");
    } else {
      printf("DEBUG: No equals found in pair\n");
    }
    
    pair = strtok(NULL, "&");
    printf("DEBUG: Next pair = [%s]\n", pair);
  }

    fprintf(file, "---\n");
    fclose(file);
}

int main() {

  int sockfd, new_fd;
  struct addrinfo hints, *res, *p;
  struct sockaddr_storage client_addr;
  int yes = 1;
  int status = 0;
  socklen_t client_len;
  char buffer[BUFFER_SIZE] = {0};
  ssize_t bytes_received = 0;
  char method[16];
  char path[256];
  char version[16];


  // Create server struct
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  // Get addrinfo
  status = getaddrinfo(NULL, PORT, &hints, &res);
  if (status == -1) {
    perror("getaddrinfo");
    return -1;
  }
  
  // loop, create socket, setsockopt, bind 
  for (p = res; p != NULL; p = p->ai_next) {
    // create socket 
    sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (sockfd == -1) {
      perror("socket");
      continue;
    }

    // setsockopt()
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
      perror("setsockopt");
      exit(1);
    }

    // bind
    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      perror("bind");
      continue;
    }

    break;
  }

  freeaddrinfo(res);

  if (p == NULL) {
    perror("failed to bind");
    exit(1);
  }

  // listen
  if (listen(sockfd, BACKLOG) == -1) {
    perror("listen");
    exit(1);
  }

  SSL_CTX *ssl_ctx = setup_tls();
  if (!ssl_ctx) {
    perror("failed to create context");
    exit(EXIT_FAILURE);
  }

  printf("HTTPS Listening on %s\n", PORT);

  while(1) {

    // accept
    client_len = sizeof(client_addr);
    new_fd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
    if (new_fd == -1) {
      perror("accept");
      continue;
    }

    // TLS handshake per connection
    SSL *ssl = SSL_new(ssl_ctx);
    if (!ssl) {
      perror("TLS handshake failed");
      continue;
    }

    if (SSL_set_fd(ssl, new_fd) == -1) {
      perror("Failed to set fd with SSL");
      continue;
    }
    
    printf("Performing TLS handshake...\n");

    if (SSL_accept(ssl) == -1) {
      fprintf(stderr, "SSL_accept failed\n");
      ERR_print_errors_fp(stderr);
      SSL_free(ssl);
      close(new_fd);
      continue;
    }


    bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1); // receive bytes

    if (bytes_received > 0) {
      buffer[bytes_received] = '\0'; // adds a null terminator to the end of message
      printf("Received HTTPS Request: \n%s\n", buffer);

      if (sscanf(buffer, "%s %s %s", method, path, version) == 3){

        // HANDLE REQUESTS 
        if (strcmp(method, "GET") == 0) {
          char filepath[512];

          if (strcmp(path, "/") == 0) {
            strcpy(filepath, "www/index.html");
          }
          else if (strcmp(path, "/success") == 0) {
            strcpy(filepath, "www/success.html");
          }
          else if (strcmp(path, "/submit") == 0) {
            strcpy(filepath, "www/submit.html");
          }
          else {
            snprintf(filepath, sizeof(filepath), "%s", path + 1);    
          }

          send_file_response(ssl, filepath);

        } else if (strcmp(method, "POST") == 0)
        {
          if (strcmp(path, "/submit") == 0) {

            int content_length = extract_content_length(ssl, buffer);
            printf("DEBUG: content_length = %d\n", content_length);
            if (content_length == -1) {
              close(new_fd);
              continue;
            }

            char *body_start = strstr(buffer, "\r\n\r\n");
            if (body_start == NULL) {
              const char* response_400_malformed = 
                "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: text/html\r\n"
                "\r\n"
                "<html><body><h1>400 Bad Request</h1>"
                "<p>Malformed HTTP Request</p></body></html>";
              

              SSL_write(ssl, response_400_malformed, strlen(response_400_malformed));
              printf("400 Bad Request: Malformed HTTP Request\n");
              return -1;
            }

            // point to after \r\n\r\n
            body_start += 4;

            int body_bytes_received = bytes_received - (body_start - buffer);
            printf("DEBUG: body_bytes_received = %d\n", body_bytes_received);

            char *full_body = malloc(content_length + 1);

            memcpy(full_body, body_start, body_bytes_received);

            while(body_bytes_received < content_length) {
              ssize_t new_bytes = recv(new_fd, full_body + body_bytes_received, content_length - body_bytes_received, 0);
              if (new_bytes > 0) {
                body_bytes_received += new_bytes;
              }
            }

            full_body[content_length] = '\0';

            printf("DEBUG: full_body content: [%s]\n", full_body);
            printf("DEBUG: full_body length: %ld\n", strlen(full_body));

            post_parse_data(full_body);

            const char *response_200 = 
              "HTTP/1.1 200 OK\r\n"
              "Content-Type: text/html\r\n"
              "\r\n"
              "<html><body><h1>Success!</h1><p>Form Submitted successfully</p><a href='/'>Home</a></body></html>";
            
            
            char filepath[512];
            //SSL_write(ssl, response_200, strlen(response_200));
            strcpy(filepath, "www/success.html");
            send_file_response(ssl, filepath);
            printf("200 OK - POST processed\n");

            free(full_body);

          }
          else {
            
            const char *response_405 = 
              "HTTP/1.1 405 Method Not Allowed"
              "Content-Type: text/html\r\n"
              "\r\n"
              "<html><body><h1>405 Method Not Allowed</h1></body></html>";
            

            SSL_write(ssl, response_405, sizeof(response_405));
            printf("405 - Method Not Allowed: %s\n", method);
          }
        }
        else 
        {
          const char *response_405 = 
            "HTTP/1.1 405 Method Not Allowed"
            "Content-Type: text/html\r\n"
            "\r\n"
            "<html><body><h1>405 Method Not Allowed</h1></body></html>";
          

          SSL_write(ssl, response_405, sizeof(response_405));
          printf("405 - Method Not Allowed: %s\n", method);
        }
      }

    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(new_fd);

  }

  close(sockfd);

  return 0;

}
