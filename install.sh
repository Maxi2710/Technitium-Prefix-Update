#!/bin/bash

set -e

TARGET_DIR="/opt/technitium/ipv6_prefix_update"

echo "Update system"
sudo apt update

echo "Install python and dependencies"
sudo apt install -y python3 python3-requests python3-yaml

echo "Create folder for python scripts"
sudo mkdir -p "$TARGET_DIR"

echo "Move all .py and .yml"
shopt -s nullglob
FILES=(*.py *.yml)
if [ ${#FILES[@]} -gt 0 ]; then
    sudo mv "${FILES[@]}" "$TARGET_DIR/"
else
    echo "No .py or .yml file found."
fi
shopt -u nullglob

echo "Create user technitium"
if ! id technitium >/dev/null 2>&1; then
    sudo useradd -r -s /usr/sbin/nologin technitium
fi

echo "Create systemd"
sudo tee /etc/systemd/system/technitium-prefix-updater.service > /dev/null <<'EOF'
[Unit]
Description=Automatic IPv6 prefix updater for Technitium
After=network.target

[Service]
Type=simple
User=technitium
Group=technitium
WorkingDirectory="$TARGET_DIR"
ExecStart=/usr/bin/python3 "$TARGET_DIR"/http_handler.py

Restart=on-failure
RestartSec=5

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

echo "Set user permissions"
sudo chown -R technitium:technitium /opt/technitium/ipv6_prefix_update

echo "Reload systemd"
sudo systemctl daemon-reexec
sudo systemctl daemon-reload

echo "Enable and start service"
sudo systemctl enable technitium-prefix-updater
sudo systemctl start technitium-prefix-updater
