

// ========================================
// HTTP SERVER WITH TLS SUPPORT
// Author: Ethan Martin
// Purpose: Learning network security
// ========================================



#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>

#define PORT "8080"
#define BACKLOG 1
#define BUFFER_SIZE 8192

// ========================================
// FILE RESPONSE HANDLER
// Serves static files over HTTP
// Returns 404 if file not found
// ========================================

void send_file_response(int new_fd, const char* filepath) {
  FILE *file = fopen(filepath, "r");

  if (file == NULL) {
    const char* response_404 = 
      "HTTP/1.1 404 Not Found\r\n"
      "Content-Type: text/html\r\n"
      "\r\n"
      "<html><body><h1>404 Not Found</h1><p>The file does not exit</p></body></html>";
    

    send(new_fd, response_404, strlen(response_404), 0);
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
    

    send(new_fd, response_500, strlen(response_500), 0);
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
  send(new_fd, response, header_len, 0);

  // send file content 
  send(new_fd, file_content, size, 0);

  printf("200 OK - Sent file: %s (%ld bytes)\n", filepath, size);
  free(file_content);
                          
}


// ========================================
// CONTENT-LENGTH EXTRACTION
// Parses HTTP headers for Content-Length
// Returns -1 if invalid/missing
// ========================================
int extract_content_length(int new_fd, const char* buffer) {
  
  const char* response_400 = 
    "HTTP/1.1 400 Bad Request\r\n"
    "Content-Type: text/html\r\n"
    "\r\n"
    "<html><body><h1>400 Bad Request</h1>"
    "<p>Missing or Invalid Content-Length Header</p></body></html>";
  

  char* result = strstr(buffer, "Content-Length:");
  if (result == NULL) {
    send(new_fd, response_400, strlen(response_400),0);
    printf("400 Bad Request: Missing Content-Length\n");
    return -1;
  }
  

  // jump to the end of "Content-Length: ", extract decimal integer, store in content_length
  int content_length;
  if (sscanf(result + 15, "%d", &content_length) != 1) {
    send(new_fd, response_400, strlen(response_400), 0);
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
  printf("Listening on %s\n", PORT);

  while(1) {

    // accept
    client_len = sizeof(client_addr);
    new_fd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
    if (new_fd == -1) {
      perror("accept");
      return -1;
    }

    bytes_received = recv(new_fd, buffer, sizeof(buffer) - 1, 0); // receive bytes

    if (bytes_received > 0) {
      buffer[bytes_received] = '\0'; // adds a null terminator to the end of message
      printf("Received HTTP Request: \n%s\n", buffer);

      if (sscanf(buffer, "%s %s %s", method, path, version) == 3){

        // HANDLE REQUESTS 
        if (strcmp(method, "GET") == 0) {
          char filepath[512];

          if (strcmp(path, "/") == 0) {
            strcpy(filepath, "index.html");
          }
          else if (strcmp(path, "/about") == 0) {
            strcpy(filepath, "about.html");
          } 
          else if (strcmp(path, "/submit") == 0) {
            strcpy(filepath, "submit.html");
          }
          else {
            snprintf(filepath, sizeof(filepath), "%s", path + 1);    
          }

          send_file_response(new_fd, filepath);

        } else if (strcmp(method, "POST") == 0)
        {
          if (strcmp(path, "/submit") == 0) {

            int content_length = extract_content_length(new_fd, buffer);
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
              

              send(new_fd, response_400_malformed, strlen(response_400_malformed), 0);
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
            

            send(new_fd, response_200, strlen(response_200), 0);
            printf("200 OK - POST processed\n");

            free(full_body);

          }
          else {
            
            const char *response_405 = 
              "HTTP/1.1 405 Method Not Allowed"
              "Content-Type: text/html\r\n"
              "\r\n"
              "<html><body><h1>405 Method Not Allowed</h1></body></html>";
            

            send(new_fd, response_405, sizeof(response_405), 0);
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
          

          send(new_fd, response_405, sizeof(response_405), 0);
          printf("405 - Method Not Allowed: %s\n", method);
        }
      }

    }
    close(new_fd);

  }

  close(sockfd);

  return 0;

}
