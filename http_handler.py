#!/usr/bin/env python3

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import subprocess
import ipaddress
import logging
import socket
import signal
import yaml
import sys

BASE_DIR = "/opt/technitium/ipv6_prefix_update"

YAML_CONFIG = f"{BASE_DIR}/config.yml"
UPDATE_SCRIPT = f"{BASE_DIR}/update_records.py"
PTR_SCRIPT = f"{BASE_DIR}/update_ptr.py"

HOST = "::"
PORT = 8080
TIMEOUT = 30
HTTP_TIMEOUT = 10

server = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s"
)

#--------------------------------------------------------------Yaml Config and Layer 8 Problem Handling--------------------------------------------------------------#

#Check if key is missing or empty
def require_config(config, path):

    value = config
    
    #Check if key is missing
    for key in path:
        if not isinstance(value, dict) or key not in value:
            logging.error(f"Config error: Missing key '{'.'.join(path)}'")
            sys.exit(1)
        value = value[key]

    #Check if key is empty
    if value is None or value == "":
        logging.error(f"Config error: '{'.'.join(path)}' is empty")
        sys.exit(1)

    return value


#Load Yaml Config
try:
    #Open yaml config file
    with open(YAML_CONFIG, "r") as f:
        config = yaml.safe_load(f) or {}

    #Check if yaml config is empty
    if not isinstance(config, dict):
        logging.error("Config error: YAML root must be a mapping")
        sys.exit(1)

#Error if file not found
except FileNotFoundError:
    logging.error(f"Error: Config file '{YAML_CONFIG}' not found")
    sys.exit(1)

#Error if yaml file not readable
except yaml.YAMLError as e:
    logging.error("Error reading config file:", e)
    sys.exit(1)


#Write keys from Yaml file into variables
prefix_length = require_config(config, ["general", "isp_prefix_length"])
api_token = require_config(config, ["general", "api_token"])
ptr = require_config(config, ["dns", "ptr"])
zone_names = require_config(config, ["zones"])


#Check if given Prefix length is valid
if not isinstance(prefix_length, int) or not (1 <= prefix_length <= 64):
    logging.error("Config error: general.isp_prefix_length must be an integer between 1 and 64")
    sys.exit(1)

#Check if PTR is True or False
if not isinstance(ptr, bool):
    logging.error("Config error: dns.ptr must be True or False")
    sys.exit(1)

#Check if Zone names are in a list and not empty
if not isinstance(zone_names, list) or not zone_names:
    logging.error("Config error: zones must be a non-empty list")
    sys.exit(1)


#--------------------------------------------------------------Functions--------------------------------------------------------------#

#Run python script in a subprocess
def run_script(label, args):
    #Run script and capture output
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=TIMEOUT
        )
    except Exception as e:
        raise RuntimeError(f"{label}: {e}")

    if result.stdout:
        for line in result.stdout.rstrip().splitlines():
            logging.info("[%s] %s", label, line)

    if result.stderr:
        for line in result.stderr.rstrip().splitlines():
            logging.error("[%s] %s", label, line)

    if result.returncode != 0:
        raise RuntimeError(f"{label} failed")


#Shutdown HTTP server
def shutdown(signum, frame):
    logging.info("Shutting down HTTP server")
    if server:
        server.shutdown()

#--------------------------------------------------------------HTTP Handler--------------------------------------------------------------#

class ThreadingHTTPServerV6(ThreadingHTTPServer):
    address_family = socket.AF_INET6

#HTTP server
class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.request.settimeout(HTTP_TIMEOUT)
        self.close_connection = True

        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)

        #Check if shared secret is set
        token = qs.get("token", [None])[0]
        if token != api_token:
            self.send_error(403, "forbidden")
            return

        #Check if IP was given
        ip = qs.get("ip", [None])[0]
        if not ip:
            self.send_error(400, "missing ip")
            return

        #Check if given IP is a valid IPv6 address
        try:
            ipv6 = ipaddress.IPv6Address(ip)
        except ValueError:
            self.send_error(400, "invalid IPv6")
            return

        #Check if IP address is global
        if not ipv6.is_global:
            self.send_error(400, f"Given address {ipv6} is not global")
            return

        #Extract the prefix from the address
        prefix = ipaddress.IPv6Network(f"{ipv6}/{prefix_length}", strict=False)
        prefix_str = str(prefix)

        #Update records and ptr zones
        try:
            #Update records from every given zone
            for zone in zone_names:
                run_script(
                    zone,
                    ["python3", UPDATE_SCRIPT, zone, prefix_str]
                )

            #Update all GUA ptr zones
            if ptr:
                run_script(
                    "PTR",
                    ["python3", PTR_SCRIPT, prefix_str]
                )

        except RuntimeError as e:
            self.send_error(500, str(e))
            return

        #Send response
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b"OK\n")


#--------------------------------------------------------------Main--------------------------------------------------------------#

#Start HTTP server and serve forever
if __name__ == "__main__":
    #Signal from systemd to shutdown
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    server = ThreadingHTTPServerV6((HOST, PORT), Handler)
    logging.info(f"Listening on {HOST}:{PORT}")
    logging.info("Usage: curl [http://2001:db8::10]:8080/?ip=2001:db10::1&token=supersecrettoken")
    
    server.serve_forever()
