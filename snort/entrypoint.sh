#!/bin/sh
set -e

BRIDGE=$(awk '$2 == "00001CAC" && $1 ~ /^br-/ {print $1; exit}' /proc/net/route)

if [ -n "$BRIDGE" ]; then
    echo "Snort monitoring ${BRIDGE} (WebGoat traffic) and wlp4s0 (LAN traffic)"
    exec /home/snorty/snort3/bin/snort -c /etc/snort/snort.lua -k none -i "$BRIDGE" -i wlp4s0 -l /var/log/snort
fi

echo "Snort monitoring wlp4s0 only"
exec /home/snorty/snort3/bin/snort -c /etc/snort/snort.lua -k none -i wlp4s0 -l /var/log/snort
