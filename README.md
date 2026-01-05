# Technitium-Prefix-Update

Technitium-Prefix-Update provides a lightweight HTTP-based service for Technitium DNS Server that dynamically updates DNS records when an IPv6 prefix changes.

It is designed for environments where the ISP regularly changes the globally routed IPv6 prefix.

The service receives a global IPv6 address via HTTP, extracts the configured prefix, and updates:

* Primary DNS zones (AAAA records)
* Optional reverse DNS zones (PTR records)

---

## How It Works

1. A client (router, script, or monitoring system) sends an HTTP request containing:

   * an IPv6 address
   * an API token (shared secret)

2. The server:

   * validates the token and IPv6 address
   * ensures the address is globally routable
   * calculates the IPv6 prefix based on the configured prefix length
   * updates the prefix for all AAAA records in the configured zones
   * optionally updates PTR zones by changing the zone name to match the new prefix

> **Note:**
> The PTR update feature currently ignores advanced zone settings such as **DNSSEC**.
> If you are using DNSSEC, **disable PTR updates**.

---

## Example Request

```bash
curl "http://[2001:db8::10]:8080/?ip=2001:db8:abcd::1&token=supersecrettoken"
```

### Successful Response

```text
OK
```

---

## Installation

### Install Git

```bash
sudo apt update && sudo apt install git
```

### Clone Repository and Run Install Script

```bash
git clone https://github.com/Maxi2710/Technitium-Prefix-Update.git
cd Technitium-Prefix-Update/
sudo bash install.sh
```

### Optional: Remove Installation Files

```bash
cd ..
rm -r Technitium-Prefix-Update/
```

### Configure the Service

Edit the configuration file:

```bash
nano /opt/technitium/ipv6_prefix_update/config.yml
```

Make sure to configure:

* API token
* Prefix length
* Zone names
* (Optional) PTR zones

---

## Manage systemd Daemon

### Show Status and Logs

```bash
systemctl status technitium-prefix-updater.service
```

### Restart Service

```bash
systemctl restart technitium-prefix-updater.service
```

### Start / Stop Service

```bash
systemctl start technitium-prefix-updater.service
systemctl stop technitium-prefix-updater.service
```

### Enable / Disable Autostart

```bash
systemctl enable technitium-prefix-updater.service
systemctl disable technitium-prefix-updater.service
```

---

## Notes

*By default the HTTP server only listens on all ipv6 addresses
