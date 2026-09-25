#!/bin/sh
set -e

echo "Snort monitoring enp0s3 (LAN traffic)"
exec /home/snorty/snort3/bin/snort -c /etc/snort/snort.lua -k none -i enp0s3 -l /var/log/snort