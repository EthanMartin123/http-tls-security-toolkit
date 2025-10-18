import socket
import ssl
import sys
import argparse
from colorama import Fore, Style, init
import warnings

init(autoreset=True)

warnings.filterwarnings("ignore", category=DeprecationWarning)

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

vulnerabilities = []

def check_ciphers(host, port):
    print(Fore.CYAN + Style.BRIGHT + "\nScanning for Weak Ciphers... \n")
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

                    vulnerabilities.append((cipher, negotiated, protocol))
                    print(Fore.RED + Style.BRIGHT + f" ⚠️ VULNERABLE: {ssock.cipher()}")
                    print(Fore.RED + Style.BRIGHT + f"    Negotiated {negotiated[0]} ({protocol})")

        except ssl.SSLError as e:
            print(Fore.GREEN + Style.BRIGHT + f" ✅ REJECTED: {cipher} ")
        except Exception as e:
            print(f" ❌ ERROR: {cipher} ({e}) ")

def test_protocol_versions(host, port):
    print(Fore.CYAN + Style.BRIGHT + "\nTesting Protocol Version... \n")

    protocols = {
        'TLS 1.0': ssl.TLSVersion.TLSv1,
        'TLS 1.1': ssl.TLSVersion.TLSv1_1,
        'TLS 1.2': ssl.TLSVersion.TLSv1_2,
        'TLS 1.3': ssl.TLSVersion.TLSv1_3,
    }

    supported = []
    deprecated = []

    for name, version in protocols.items():
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = version 
            context.maximum_version = version
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    if version < ssl.TLSVersion.TLSv1_2:
                        print(Fore.RED + Style.BRIGHT + f" ⚠️ DEPRECATED: {name}")
                        deprecated.append(name)
                        vulnerabilities.append(name)
                    else:
                        supported.append(name)
                        print(Fore.GREEN + Style.BRIGHT + f" ✅ SUPPORTED: {name}")
        except:
            print(Fore.YELLOW + f" ❌ NOT SUPPORTED: {name}")
    return supported, deprecated


def print_summary(vulnerabilities, deprecated, supported):
    print("\n" + "="*70)
    print("SCAN SUMMARY")
    print("="*70)
    print(f"Total weak ciphers tested: {len(weak_ciphers)}")
    print(f"TLS versions supported: {supported}")

    if len(deprecated) == 0:
        print(Fore.GREEN + Style.BRIGHT + f"Deprecated TLS versions supported: NONE")
    else:
        print(Fore.RED + Style.BRIGHT + f"Deprecated TLS versions supported: {deprecated}")

    if len(vulnerabilities) == 0:
        print(Fore.GREEN + Style.BRIGHT + f"Vulnerabilities found: NONE")
    else:
        print(Fore.RED + Style.BRIGHT + f"Vulnerabilities found: {len(vulnerabilities)}")

    if vulnerabilities:
        print(Fore.YELLOW + Style.BRIGHT + "\n⚠️ RECOMMENDATIONS:")
        print(Fore.YELLOW + Style.BRIGHT + "   -> Remove weak ciphers from server configuration")
        print(Fore.YELLOW + Style.BRIGHT + "   -> Use only TLS 1.2+ with AEAD ciphers\n")


if __name__ == "__main__":
    check_ciphers(HOST,PORT)
    supported, deprecated = test_protocol_versions(HOST, PORT)
    print_summary(vulnerabilities, deprecated, supported)
