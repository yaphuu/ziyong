#!/bin/bash
# WebWatch v3 - nginx + Cloudflare aware security observer
# Uses the actual nginx log_format shown by this VPS:
# $remote_addr ... "$http_user_agent" "$http_x_forwarded_for"
# GeoIP is local only.

set -u

LOG="${LOG:-/var/log/nginx/access.log}"
CITY_DB="${CITY_DB:-/usr/share/GeoIP/GeoLite2-City.mmdb}"
ASN_DB="${ASN_DB:-/usr/share/GeoIP/GeoLite2-ASN.mmdb}"
JQ="/usr/local/bin/jq"
MMDB="/usr/bin/mmdbinspect"
REPORT="${REPORT:-/var/log/webwatch.log}"
CACHE="${CACHE:-/var/lib/webwatch/ip-cache}"
DURATION="${DURATION:-24h}"

mkdir -p "$CACHE"
touch "$REPORT" || { echo "ERROR: cannot write $REPORT"; exit 1; }

for f in "$LOG" "$CITY_DB" "$ASN_DB" "$JQ" "$MMDB"; do
    [ -e "$f" ] || { echo "ERROR: missing $f"; exit 1; }
done
[ -x "$JQ" ] || { echo "ERROR: $JQ is not executable"; exit 1; }
[ -x "$MMDB" ] || { echo "ERROR: $MMDB is not executable"; exit 1; }

geo() {
    local ip="$1" city asn
    city="$("$MMDB" -jsonl -db "$CITY_DB" "$ip" 2>/dev/null |
        "$JQ" -r '.record | [
          (.country.names["zh-CN"] // .country.names.en // "未知"),
          (.subdivisions[0].names["zh-CN"] // .subdivisions[0].names.en // ""),
          (.city.names["zh-CN"] // .city.names.en // ""),
          (.location.latitude // ""),
          (.location.longitude // ""),
          (.location.accuracy_radius // "")
        ] | @tsv' 2>/dev/null | head -n1)"

    asn="$("$MMDB" -jsonl -db "$ASN_DB" "$ip" 2>/dev/null |
        "$JQ" -r '.record | [
          (if .autonomous_system_number then
             "AS" + (.autonomous_system_number|tostring)
           else "未知" end),
          (.autonomous_system_organization // "未知")
        ] | @tsv' 2>/dev/null | head -n1)"

    printf '%s|%s' "${city:-未知}" "${asn:-未知}"
}

echo "============================================================"
echo " WebWatch v3 - nginx + Cloudflare aware"
echo " Log      : $LOG"
echo " Report   : $REPORT"
echo " Started  : $(date '+%F %T')"
echo " Duration : $DURATION"
echo "============================================================"
echo "$(date '+%F %T') START" >> "$REPORT"

timeout --foreground "$DURATION" tail -Fn0 "$LOG" | while IFS= read -r line; do

    # Actual nginx log format:
    # $remote_addr - $remote_user [$time_local] "$request"
    # $status $body_bytes_sent "$http_referer"
    # "$http_user_agent" "$http_x_forwarded_for"

    proxy_ip="$(awk '{print $1}' <<<"$line")"

    # Extract the final two quoted fields:
    #   quoted field 1 = User-Agent
    #   quoted field 2 = X-Forwarded-For
    ua=""
    forwarded=""
    parsed="$(sed -n 's/.*"[^"]*" "\([^"]*\)" "\([^"]*\)"$/\1\t\2/p' <<<"$line")"
    if [ -n "$parsed" ]; then
        ua="${parsed%%$'\t'*}"
        forwarded="${parsed#*$'\t'}"
    fi

    # X-Forwarded-For may contain a comma-separated chain.
    # For this Cloudflare setup, use the first client address.
    client_ip="$forwarded"
    if [ "$client_ip" != "-" ] && [[ "$client_ip" == *,* ]]; then
        client_ip="${client_ip%%,*}"
        client_ip="$(sed 's/^[[:space:]]*//;s/[[:space:]]*$//' <<<"$client_ip")"
    fi

    # If XFF is absent, treat the nginx peer as the client.
    if [ -z "$client_ip" ] || [ "$client_ip" = "-" ]; then
        client_ip="$proxy_ip"
        via="direct"
        proxy_display="-"
    else
        via="X-Forwarded-For"
        proxy_display="$proxy_ip"
    fi

    [[ "$client_ip" == "-" || -z "$client_ip" ]] && continue
    [[ "$client_ip" == "127.0.0.1" || "$client_ip" == "::1" ]] && continue

    request="$(sed -n 's/.*"\(GET\|POST\|HEAD\|PUT\|DELETE\|OPTIONS\|PATCH\) \([^"]*\) HTTP\/[^"]*".*/\1 \2/p' <<<"$line")"
    status="$(awk '{for(i=1;i<=NF;i++) if($i ~ /^[1-5][0-9][0-9]$/){print $i; exit}}' <<<"$line")"

    risk="NORMAL"
    reason=""

    if grep -Eqi '(\.git([/?]|$)|(^|[/?])\.env([/?]|$)|wp-login\.php|xmlrpc\.php|wp-admin|wp-includes|phpmyadmin|phpinfo|actuator([/?]|$)|cgi-bin|eval-stdin|/bin/sh|/bin/bash|%2e|%252e|%2f|%252f|/etc/passwd|/proc/self|jndi:|union([+%20]|%20)+select|select.+from)' <<<"$request"; then
        risk="HIGH"
        reason="典型漏洞/后门/敏感文件探测"
    elif [[ "$status" == "400" || "$status" == "401" || "$status" == "403" || "$status" == "404" ]]; then
        risk="WATCH"
        reason="异常/不存在资源请求"
    fi

    key="$(printf '%s' "$client_ip" | tr ':' '_')"
    cachefile="$CACHE/$key"
    if [ ! -s "$cachefile" ]; then
        geo "$client_ip" > "$cachefile"
    fi

    geo_info="$(<"$cachefile")"
    city_info="${geo_info%%|*}"
    asn_info="${geo_info#*|}"

    # Split City information for readable output.
    IFS=$'\t' read -r country region city lat lon radius <<<"${city_info//$'|'/	}"

    case "$risk" in
        HIGH)  tag="HIGH" ;;
        WATCH) tag="WATCH" ;;
        *)     tag="NORMAL" ;;
    esac

    {
        echo
        echo "------------------------------------------------------------"
        echo "$(date '+%F %T')  [$tag]"
        echo "访问IP       : $client_ip"
        echo "代理/对端IP  : $proxy_display"
        echo "方式         : $via"
        echo "归属国家     : ${country:-未知}"
        echo "州/省        : ${region:-}"
        echo "城市         : ${city:-}"
        echo "坐标         : ${lat:-}, ${lon:-}"
        echo "定位半径(km) : ${radius:-}"
        echo "ASN          : $asn_info"
        echo "请求         : ${request:-unknown}"
        echo "状态         : ${status:-unknown}"
        echo "User-Agent   : ${ua:-unknown}"
        [ -n "$reason" ] && echo "原因         : $reason"
    } | tee -a "$REPORT"

done

echo "$(date '+%F %T') END" >> "$REPORT"
echo "WebWatch finished."
