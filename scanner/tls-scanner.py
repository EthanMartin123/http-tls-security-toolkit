import socket
import ssl 

HOST = "localhost"
PORT = 8080


weak_ciphers = ["RC4-SHA", "EXP-RC4-MD5", "NULL-SHA"]
 


for cipher in weak_ciphers:
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.set_ciphers(cipher)
        context.load_verify_locations('certs/cert.pem')
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        with socket.create_connection((HOST, PORT)) as sock:
            with context.wrap_socket(sock, server_hostname=HOST) as ssock:
                print(f"SUCCESS: Connection established with cipher suite: {cipher}")
    except ssl.SSLError as e:
        print(f"FAILED: Connection failed with {cipher} ({e}) ")
    except Exception as e:
        print(f"ERROR: {e} ")
