#!/bin/bash
# geoip-update.sh
# Run daily. geoipupdate checks for a new database and only downloads when needed.
# Credentials must be stored in /etc/GeoIP.conf (chmod 600), never in GitHub.

set -e

CONF="/etc/GeoIP.conf"
DBDIR="/usr/share/GeoIP"

if [ ! -x /usr/bin/geoipupdate ]; then
    echo "ERROR: /usr/bin/geoipupdate is not installed."
    echo "Install the official MaxMind geoipupdate package first."
    exit 1
fi

mkdir -p "$DBDIR"
chmod 700 "$DBDIR"

# geoipupdate replaces the database with the current release.
# Do not delete the current DB before a successful update.
GEOIPUPDATE_CONFIG_FILE="$CONF" /usr/bin/geoipupdate -v

# Keep only the current MMDB files; never keep old GeoLite databases here.
find "$DBDIR" -maxdepth 1 -type f \
  \( -name 'GeoLite2-City.mmdb.*' -o -name 'GeoLite2-ASN.mmdb.*' \) \
  -delete

echo "GeoIP database update finished: $(date '+%F %T')"
