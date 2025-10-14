CC = gcc
CFLAGS = -Wall -Wextra -std=c11
LDFLAGS = -lssl -lcrypto

SRC_DIR = src
BUILD_DIR = build
CERT_DIR = certs

TARGET = server
SRC = $(SRC_DIR)/server.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)
	@echo "✅ Server compiled successfully!"

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
	@echo "🧹 Cleaned build artifacts"

certs:
	@if  [ ! -f $(CERT_DIR)/cert.pem ]; then \
		echo "🔐 Generating SSL certificates... "; \
		cd $(CERT_DIR) && ./generate-cert.sh; \
	else \
		echo "✅ Certificates already exist!"; \
	fi

setup: certs all
	@echo "✅ Setup complete! Run 'make run' to start the server"

debug: CFLAGS += -g -DDEBUG
debug: clean $(TARGET)
	@echo "🐛 Debug build complete"

valgrind: $(TARGET)
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./$(TARGET)

help:
	@echo "Available targets:"
	@echo "  make           - Compile the server (default)"
	@echo "  make run       - Compile and run the server"
	@echo "  make clean     - Remove compiled binary"
	@echo "  make certs     - Generate SSL certificates"
	@echo "  make setup     - Generate certs and compile"
	@echo "  make debug     - Compile with debug symbols"
	@echo "  make valgrind  - Run with memory leak detection"
	@echo "  make help      - Show this help message"

.PHONY: all run clean certs setup debug valgrind help
