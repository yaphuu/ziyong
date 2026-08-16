#!/bin/bash
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
          (.location.longitude // "")
        ] | @tsv' 2>/dev/null | head -n1)"
    asn="$("$MMDB" -jsonl -db "$ASN_DB" "$ip" 2>/dev/null |
        "$JQ" -r '.record | [
          (if .autonomous_system_number then "AS" + (.autonomous_system_number|tostring) else "未知" end),
          (.autonomous_system_organization // "未知")
        ] | @tsv' 2>/dev/null | head -n1)"
    printf '%s|%s' "${city:-未知}" "${asn:-未知}"
}

echo "============================================================"
echo " WebWatch - nginx realtime security observer"
echo " Log      : $LOG"
echo " Report   : $REPORT"
echo " Started  : $(date '+%F %T')"
echo " Duration : $DURATION"
echo "============================================================"
echo "$(date '+%F %T') START" >> "$REPORT"

timeout --foreground "$DURATION" tail -Fn0 "$LOG" | while IFS= read -r line; do
    source_ip="$(awk '{print $1}' <<<"$line")"
    forwarded="$(awk '{print $NF}' <<<"$line" | tr -d '"')"

    if [[ "$forwarded" =~ ^[0-9a-fA-F:.]+$ ]]; then
        ip="$forwarded"
        proxy="$source_ip"
        via="X-Forwarded-For"
    else
        ip="$source_ip"
        proxy="-"
        via="direct"
    fi

    [[ "$ip" == "-" || -z "$ip" ]] && continue
    [[ "$ip" == "127.0.0.1" || "$ip" == "::1" ]] && continue

    request="$(sed -n 's/.*"\(GET\|POST\|HEAD\|PUT\|DELETE\|OPTIONS\|PATCH\) \([^"]*\) HTTP\/[^"]*".*/\1 \2/p' <<<"$line")"
    status="$(awk '{for(i=1;i<=NF;i++) if($i ~ /^[1-5][0-9][0-9]$/){print $i; exit}}' <<<"$line")"
    ua="$(sed -n 's/.*"\([^"]*\)"[[:space:]]*$/\1/p' <<<"$line")"

    risk="NORMAL"
    reason=""
    if grep -Eqi '(\.git([/?]|$)|(^|[/?])\.env([/?]|$)|wp-login\.php|xmlrpc\.php|wp-admin|wp-includes|phpmyadmin|phpinfo|actuator([/?]|$)|cgi-bin|eval-stdin|/bin/sh|/bin/bash|%2e|%252e|%2f|%252f|/etc/passwd|/proc/self|jndi:|union([+%20]|%20)+select|select.+from)' <<<"$request"; then
        risk="HIGH"
        reason="典型漏洞/后门/敏感文件探测"
    elif [[ "$status" == "400" || "$status" == "401" || "$status" == "403" || "$status" == "404" ]]; then
        risk="WATCH"
        reason="异常/不存在资源请求"
    fi

    key="$(printf '%s' "$ip" | tr ':' '_')"
    cachefile="$CACHE/$key"
    if [ ! -s "$cachefile" ]; then
        geo "$ip" > "$cachefile"
    fi
    geo_info="$(<"$cachefile")"
    city_info="${geo_info%%|*}"
    asn_info="${geo_info#*|}"

    case "$risk" in
        HIGH)  tag="HIGH" ;;
        WATCH) tag="WATCH" ;;
        *)     tag="NORMAL" ;;
    esac

    {
        echo
        echo "------------------------------------------------------------"
        echo "$(date '+%F %T')  [$tag]"
        echo "访问IP : $ip"
        echo "来源IP : $proxy"
        echo "方式   : $via"
        echo "归属地 : $city_info"
        echo "ASN    : $asn_info"
        echo "请求   : ${request:-unknown}"
        echo "状态   : ${status:-unknown}"
        [ -n "$reason" ] && echo "原因   : $reason"
        [ -n "$ua" ] && echo "UA     : $ua"
    } | tee -a "$REPORT"
done

echo "$(date '+%F %T') END" >> "$REPORT"
echo "WebWatch finished."
