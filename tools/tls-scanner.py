import socket
import ssl
import sys
import argparse
from colorama import Fore, Style, init

init(autoreset=True)

parser = argparse.ArgumentParser(description="TLS Vulnerability Scanner")
parser.add_argument("host", help="Target hostname or IP")
parser.add_argument("port", type=int, help="Target port")
parser.add_argument("--output", choices=["text", "json"], default="text")
args = parser.parse_args()

HOST = args.host 
PORT = args.port

weak_ciphers = ["DES-CBC3-SHA", "ECDHE-RSA-DES-CBC3-SHA", "AES128-SHA", "AES256-SHA",
                "ECDHE-RSA-AES128-SHA", "ECDHE-RSA-AES256-SHA", 
                "DHE-RSA-AES128-SHA", "DHE-RSA-AES256-SHA"]

def check_ciphers(host, port):
    vulnerable = []
    for cipher in weak_ciphers:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

            context.maximum_version = ssl.TLSVersion.TLSv1_2
            context.minimum_version = ssl.TLSVersion.TLSv1_2

            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_ciphers(cipher)

            with socket.create_connection((host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    negotiated = ssock.cipher()
                    protocol = ssock.version()

                    vulnerable.append((cipher, negotiated, protocol))
                    print(Fore.RED + Style.BRIGHT + f" ⚠️ VULNERABLE: {ssock.cipher()}")
                    print(Fore.RED + Style.BRIGHT + f"    Negotiated {negotiated[0]} ({protocol})")

        except ssl.SSLError as e:
            print(Fore.GREEN + Style.BRIGHT + f" ✅ REJECTED: {cipher} ")
        except Exception as e:
            print(f" ❌ ERROR: {cipher} ({e}) ")


if __name__ == "__main__":
    check_ciphers(HOST,PORT)
