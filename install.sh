!/bin/bash

set -e

TARGET_DIR="/opt/technitium/ipv6_prefix_update"

echo "Update system"
sudo apt update

echo "Install python and dependencies"
sudo apt install -y python3 python3-requests python3-yaml

echo "Create folder for python scripts"
sudo mkdir -p "$TARGET_DIR"

echo "Move all .py and .yml"
FOUND=0
for file in *.py *.yml; do
    if [ -f "$file" ]; then
        sudo mv "$file" "$TARGET_DIR/"
        FOUND=1
    fi
done

if [ "$FOUND" -eq 0 ]; then
    echo "Keine .py oder .yml Dateien zum Verschieben gefunden."
fi

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
WorkingDirectory=/opt/technitium/ipv6_prefix_update
ExecStart=/usr/bin/python3 /opt/technitium/ipv6_prefix_update/http_handler.py

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
