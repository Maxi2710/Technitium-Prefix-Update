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
ptr = require_config(config, ["dns", "ptr"])

#Check if ttl is not 0
if not isinstance(ttl, int) or ttl <= 0:
    print("Config error: dns.ttl must be a positive integer")
    sys.exit(1)

#check if ptr is boolean
if not isinstance(ptr, bool):
    print("Config error: dns.ptr must be True or False")
    sys.exit(1)

#--------------------------------------------------------------Argument Parsing--------------------------------------------------------------#

def parse_args():
    parser = argparse.ArgumentParser(
        description="Update IPv6 ptr zones for Technitium"
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

#Reads all zones from the API and filters for ipv6 and ptr
def read_ipv6_ptr_zones (session, url, token):
    #Call API
    data = api_get(
        session,
        f"{url}/api/zones/list",
        params={"token": token}
    )

    zones = data.get("response", {}).get("zones", [])

    #filter only for Ipv6, not internal and Primary zones
    ptr_zones = [
        zone for zone in zones
        if zone["name"].endswith(".ip6.arpa")
        and not zone.get("internal", False)
        and zone.get("type") == "Primary"
    ]

    return ptr_zones


#Create a Primary Zone
def create_zone(session, url, token, zone):
    #Call API
    api_get(
        session,
        f"{url}/api/zones/create",
        params={
            "token": token,
            "zone": zone,
            "type": "Primary"
        }
    )


#Delete a Zone
def delete_zone(session, url, token, zone):
    #Call API
    api_get(
        session,
        f"{url}/api/zones/delete",
        params={
            "token": token,
            "zone": zone
        }
    )


#Get records from a Zone
def get_ptr_records(session, url, token, zone):
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
    return data.get("response", {}).get("records", [])


#Add a PTR record
def add_ptr_record(session, url, token, zone, domain, ptr_target, ttl):
    #Call API
    api_get(
        session,
        f"{url}/api/zones/records/add",
        params={
            "token": token,
            "zone": zone,
            "domain": domain,
            "type": "PTR",
            "ptrName": ptr_target, #Important
            "ttl": ttl
        }
    )


#Convert reverse Zone name to Prefix
def ip6_arpa_to_prefix(zone_name):
    #Remove ending and split in nibbles
    nibbles = zone_name.replace(".ip6.arpa", "").split(".")
    #Reverse
    nibbles.reverse()

    #Join nibbles together
    hex_str = "".join(nibbles)
    #Calculate prefix length
    prefix_len = len(hex_str) * 4

    #Fill mising bits with 0
    hex_str = hex_str.ljust(32, "0")

    #create ipv6 address
    addr = ipaddress.IPv6Address(int(hex_str, 16))
    #Create prefix and return
    return ipaddress.IPv6Network((addr, prefix_len), strict=False)


#Convert Prefix to reverse Zone name
def prefix_to_ip6_arpa(network):
    #convert to 128bit integer hexadecimal
    hex_str = f"{int(network.network_address):032x}"
    #Convert to nibbles
    nibbles = hex_str[: network.prefixlen // 4]
    #Add dot between every nibble, reverse and add ending
    return ".".join(reversed(nibbles)) + ".ip6.arpa"


#Check if given ipv6 network is global (GUA)
def is_global_ipv6(network):
    return network.network_address.is_global


#Build new Prefix with old prefix and rest of old prefix
def remap_prefix(old_net, new_global):
    #Calculate subnet bits
    subnet_bits = old_net.prefixlen - new_global.prefixlen
    #Check if new Prefix is smaller than new Prefix
    if subnet_bits < 0:
        raise ValueError("New prefix is smaller than existing zone prefix")

    #Calculate the part of the prefix that has to be swapped with the new prefix
    offset = int(old_net.network_address) & ((1 << (128 - new_global.prefixlen)) - 1)
    #Swap
    new_addr = int(new_global.network_address) | offset

    return ipaddress.IPv6Network((new_addr, old_net.prefixlen), strict=False)


#Remove dot from the End of a FQDN if necessary, eg: "example.com. or host.example.com."
def normalize_fqdn(name: str) -> str:
    return name[:-1] if name.endswith(".") else name


#Map PTR record domain name from old zone to new zone
def map_record_domain_to_new_zone(record_name: str, old_zone: str, new_zone: str) -> str:
    #Normalize all names (remove dot from the end if necessary)
    record_name = normalize_fqdn(record_name)
    old_zone = normalize_fqdn(old_zone)
    new_zone = normalize_fqdn(new_zone)

    #Check if record has the same name as the old zone
    if record_name == old_zone:
        return new_zone

    #Add new suffix to the old zone
    suffix = "." + old_zone
    if record_name.endswith(suffix):
        return record_name[: -len(suffix)] + "." + new_zone

    #Check if record name is relative (no dots) or not a full ip6.arpa name
    if record_name.count(".") == 0 or not record_name.endswith(".ip6.arpa"):
        return record_name + "." + new_zone

    #Check if record does not belong to the old zone and cannot be mapped safely
    raise ValueError(f"Record '{record_name}' is not inside old zone '{old_zone}'")

#--------------------------------------------------------------Main--------------------------------------------------------------#

def migrate_ipv6_ptr_zones(session, zones, new_prefix):
    for zone in zones:
        #Get old zone name
        old_zone = zone["name"]

        print(f"\nProcessing zone: {old_zone}")

        #Convert old zone into a prefix 
        try:
            old_net = ip6_arpa_to_prefix(old_zone)
        except Exception as e:
            print(f"  Skipping: cannot parse zone ({e})")
            continue

        #Check if Prefix is global
        if not is_global_ipv6(old_net):
            print("  Skipping: not a global IPv6 prefix")
            continue

        #Check if prefix is nibble aligned
        if old_net.prefixlen % 4 != 0:
            print("  Skipping: prefix is not nibble-aligned")
            continue

        #Remap old prefix with new prefix
        try:
            new_net = remap_prefix(old_net, new_prefix)
        except ValueError as e:
            print(f"  Skipping: {e}")
            continue

        #Convert new Prefix back into a PTR zone name
        new_zone = prefix_to_ip6_arpa(new_net)

        print(f"  Old prefix: {old_net}")
        print(f"  New prefix: {new_net}")
        print(f"  New zone:   {new_zone}")

        #Create new zone
        try:
            create_zone(session, technitium_url, api_token, new_zone)
            print("  New zone created")
        except SystemExit:
            print("  Failed to create new zone")
            continue

        #Get all PTR records from old zone
        records = get_ptr_records(session, technitium_url, api_token, old_zone)
        copied = 0

        #Copy all ptr records from old zone into new zone and delete old zone
        for record in records:
            #Check if record ist a PTR record
            if record.get("type") != "PTR":
                continue

            #Get old domain
            old_domain = record["name"]
            rdata = record.get("rData", {}) or {}

            #Check if PTR record has a ptrName/value
            ptr_target = rdata.get("ptrName") or rdata.get("value")
            if not ptr_target:
                print(f"    Skipping PTR record without ptrName/value: {old_domain} rData={rdata}")
                continue

            try:
                new_domain = map_record_domain_to_new_zone(old_domain, old_zone, new_zone)
            except ValueError as e:
                print(f"    Skipping: {e}")
                continue

            #Add the record into the new zone
            add_ptr_record(
                session,
                technitium_url,
                api_token,
                new_zone,
                new_domain,
                ptr_target,
                ttl
            )
            copied += 1

        print(f"  Copied {copied} PTR records")

        #Delete old PTR zone
        try:
            #Don't delete old zone if no records where copied
            if copied == 0:
                print("  No records copied – old zone NOT deleted")
                continue

            delete_zone(session, technitium_url, api_token, old_zone)
            print("  Old zone deleted")
        except SystemExit:
            print("  Failed to delete old zone")


#Main function
def main():

    #Get Arguments
    args = parse_args()

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

    ptr_zones = read_ipv6_ptr_zones(session, technitium_url, api_token)

    if not ptr_zones:
        print("No IPv6 PTR zones found")
        return

    migrate_ipv6_ptr_zones(session, ptr_zones, new_prefix)


#Run main funktion
if __name__ == "__main__":
    main()
