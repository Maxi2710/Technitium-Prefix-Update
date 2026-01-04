#!/usr/bin/env python3

import ipaddress
import argparse
import requests
import yaml
import sys

YAML_CONFIG = "config.yml"
API_TIMEOUT = 10

#--------------------------------------------------------------Yaml Config and Layer 8 Problem Handling--------------------------------------------------------------#

#Check if key is missing or empty
def require_config(config, path):
    
    value = config

    #Check if key is missing
    for key in path:
        if not isinstance(value, dict) or key not in value:
            print(f"Config error: Missing key '{'.'.join(path)}'")
            sys.exit(1)
        value = value[key]

    #Check if key is empty
    if value is None or value == "":
        print(f"Config error: '{'.'.join(path)}' is empty")
        sys.exit(1)

    return value


#Load Yaml Config
try:
    #Open yaml config file
    with open(YAML_CONFIG, "r") as f:
        config = yaml.safe_load(f) or {}

    #Check if yaml config is empty
    if not isinstance(config, dict):
        print("Config error: YAML root must be a mapping")
        sys.exit(1)

#Error if file not found
except FileNotFoundError:
    print("Error: Config file named:", YAML_CONFIG, "not found")
    sys.exit(1)

#Error if yaml file not readable
except yaml.YAMLError as e:
    print("Error reading config file:", e)
    sys.exit(1)


#Write keys from Yaml file into variables
technitium_url = require_config(config, ["general", "technitium_url"])
api_token = require_config(config, ["general", "api_token"])
ttl = require_config(config, ["dns", "ttl"])


#Check if ttl is not 0
if not isinstance(ttl, int) or ttl <= 0:
    print("Config error: dns.ttl must be a positive integer")
    sys.exit(1)

#--------------------------------------------------------------Argument Parsing--------------------------------------------------------------#

def parse_args():
    parser = argparse.ArgumentParser(
        description="Update IPv6 prefixes for Technitium"
    )
    #Argument for the zone name
    parser.add_argument(
        "zone_name",
        help="DNS zone name (e.g. test.home.arpa)"
    )
    #Argument for the new Prefix
    parser.add_argument(
        "new_prefix",
        help="New IPv6 prefix (e.g. 2001:db8:1234:1200::/56)"
    )

    return parser.parse_args()

#--------------------------------------------------------------API Helper--------------------------------------------------------------#

def api_get(session, url, params):
    try:
        response = session.get(url, params=params, timeout=API_TIMEOUT)
        response.raise_for_status()
    #API connection Error handling
    except requests.exceptions.RequestException as e:
        print("HTTP/API connection error:", e)
        sys.exit(1)

    #Check if data from API is json
    try:
        data = response.json()
    except ValueError:
        print("API error: Response is not valid JSON")
        sys.exit(1)

    #Check if API response is ok
    if data.get("status") != "ok":
        print("API returned error:")
        print(data)
        sys.exit(1)

    return data

#--------------------------------------------------------------Functions--------------------------------------------------------------#

#Call technitium API and read records
def read_records(session, url, zone, token):
    
    #Call API
    data = api_get(
        session,
        f"{url}/api/zones/records/get",
        params={
            "token": token,
            "domain": zone,
            "zone": zone,
            "listZone": "true"
        }
    )

    return data["response"]["records"]


#Filter only for IPv6 global unicast records
def filter_ipv6_gua(api_response):
    addresses = []

    #Check if record is an Ipv6 address
    for r in api_response:
        if r.get("type") != "AAAA":
            continue

        #Check if IP address is present
        ip_str = r.get("rData", {}).get("ipAddress")
        if not ip_str:
            continue

        #Check if IPv6 is valid
        try:
            ip = ipaddress.IPv6Address(ip_str)
        except ValueError:
            continue

        #Check only for global unicast addresses
        if ip.is_global:
            addresses.append(r)

    return addresses


#Call technitium API to update IP address
def update_ip_address(session, url, token, domain, zone, record_type, ipAddress, newIpAddress, ttl):

    #Call API
    api_get(
        session,
        f"{url}/api/zones/records/update",
        params={
            "token": token,
            "domain": domain,
            "zone": zone,
            "type": record_type,
            "IpAddress": ipAddress,
            "newIpAddress": newIpAddress,
            "ttl": ttl
        }
    )


#Update prefix from a given IP address
def ip_prefix_update(old_ipv6: str, prefix: ipaddress.IPv6Network) -> str:

    #Convert strings to IP addresses
    old_ip = ipaddress.IPv6Address(old_ipv6)
    new_prefix = ipaddress.IPv6Network(prefix, strict=False)

     #Find out prefix lengh
    prefix_length = new_prefix.prefixlen

    #Exract host bits vom old IP
    host_bits = int(old_ip) & ((1 << (128 - prefix_length)) - 1)

    #Add new prefix with old host part
    new_ip_int = int(new_prefix.network_address) | host_bits
    return str(ipaddress.IPv6Address(new_ip_int))

#--------------------------------------------------------------Main--------------------------------------------------------------#

#Main funtion
def main():

    #Get Arguments
    args = parse_args()

    #Ge zone name form Arguments
    zone_name = args.zone_name

    #Try getting new prefix from Arguments
    try:
        new_prefix = ipaddress.IPv6Network(args.new_prefix, strict=False)
    #Error if given prefix is not valid
    except ValueError:
        print("Error:", args.new_prefix, "is not a valid IPv6 prefix")
        sys.exit(1)

    #Error if new Prefix smaller than /64
    if new_prefix.prefixlen > 64:
        print("Error: Prefix length > 64 will break SLAAC-based hosts")
        sys.exit(1)

    #Create http session
    session = requests.Session()

    #Read all records in given zone
    all_records = read_records(session, technitium_url, zone_name, api_token)

    #Filter only ipv6 gua records from alle records
    ipv6_gua_records = filter_ipv6_gua(all_records)

    #Check if gua records are present.
    if not ipv6_gua_records:
        print("No IPv6 Global Unicast records found")
        return

    #Update prefix of every ip address in given zone
    for record in ipv6_gua_records:

        domain = record.get("name")
        old_ip = record["rData"]["ipAddress"]

        #Get new IP
        new_ip = ip_prefix_update(old_ip, new_prefix)

        #Check if old IP is the same than new IP
        if old_ip == new_ip:
            print(f"Skip {domain}: IP unchanged ({old_ip})")
            continue

        print(f"Update {domain}: {old_ip} -> {new_ip}")

        #Update IP address
        update_ip_address(
            session=session,
            url=technitium_url,
            token=api_token,
            domain=domain,
            zone=zone_name,
            record_type="AAAA",
            ipAddress=old_ip,
            newIpAddress=new_ip,
            ttl=ttl
        )


#Run main funktion
if __name__ == "__main__":
    main()
