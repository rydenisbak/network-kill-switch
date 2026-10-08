#!/bin/bash
# network-kill-switch: traffic to the watched networks may leave this Mac only through a verified VPN tunnel.
#
# THE GUARANTEE is one pf rule in the anchor com.apple/000.NetworkKillSwitch:
#
#     block return out quick on ! utunN to <nks_nets>      (a verified tunnel exists)
#     block return out quick to <nks_nets>                 (no verified tunnel)
#
# The kernel applies it to every packet of every process: Claude.app, the CLI, the VS Code
# extension, and the VPN extension itself when it sends a flow "direct" past its own tunnel.
# The rule names the one interface that was verified, so a tunnel that disappears, or comes
# back under another name, is blocked with no reaction time at all; the daemon is not on the
# packet path. The anchor hangs off the stock `anchor "com.apple/*"` in /etc/pf.conf, so
# /etc/pf.conf is never edited.
#
# THE DAEMON keeps that rule correct:
#   - pins it to the VPN interface that carries the route to Anthropic, after checking through
#     that interface that the exit country is not blocked (RU, BY by default);
#   - re-checks the exit every COUNTRY_INTERVAL seconds and blocks while it is in
#     BLOCKED_COUNTRIES (RU, BY by default);
#   - re-pins on interface events (route monitor) and every TICK seconds;
#   - holds its own pf enable reference and re-loads the anchor if something flushed it;
#   - learns dedicated addresses for LEARN_DOMAINS (Anthropic, OpenAI, Datadog, Sentry,
#     and the content hosts). Shared CDN answers are not added.
#
# Commands: run | once | status | verify | version
# Sourced with CVL_LIB=1 it only defines functions (used by check.sh and the tests).
# CVL_* environment variables replace paths and binaries for the unprivileged simulation.

set -uo pipefail
export LC_ALL=C

VERSION=1.3.0

# Everything lives under /opt/network-kill-switch, owned by root. Not /usr/local: on an Intel Mac
# with Homebrew /usr/local/* belongs to the user, who could then swap what root runs.
CONFIG="${CVL_CONFIG:-/opt/network-kill-switch/network-kill-switch.conf}"
STATE_DIR="${CVL_STATE_DIR:-/opt/network-kill-switch/state}"
LOG="${CVL_LOG:-/var/log/network-kill-switch.log}"
ETC_HOSTS="${CVL_HOSTS:-/etc/hosts}"
ANCHOR="${CVL_ANCHOR:-com.apple/000.NetworkKillSwitch}"
PFCTL="${CVL_PFCTL:-/sbin/pfctl}"
ROUTE="${CVL_ROUTE:-/sbin/route}"
IFCONFIG="${CVL_IFCONFIG:-/sbin/ifconfig}"
NETSTAT="${CVL_NETSTAT:-/usr/sbin/netstat}"
CURL="${CVL_CURL:-/usr/bin/curl}"
DSCACHEUTIL="${CVL_DSCACHEUTIL:-/usr/bin/dscacheutil}"
# dig is used only with the real resolver. The simulator points DSCACHEUTIL at a fake and must
# not leak out to the network. CVL_DIG overrides either way.
DIG_BIN="${CVL_DIG:-}"
if [ -z "${DIG_BIN}" ] && [ "${DSCACHEUTIL}" = "/usr/bin/dscacheutil" ]; then
  DIG_BIN=$(command -v dig 2>/dev/null || true)
fi

# Defaults; the config file may override any of them.
PINNED_NETS="160.79.104.0/21 2607:6bc0::/32"   # Anthropic, PBC (whois AP-2440)
CANARY_NET="203.0.113.7"                       # TEST-NET-3: lets verify prove the real rule
ROUTE_PROBE="160.79.104.10"                    # only asked of the routing table, never sent to
# Names the daemon resolves into the block table. Most Anthropic API traffic already sits in
# PINNED_NETS (inbound 160.79.104.0/23 and 2607:6bc0::/48 are inside those wider nets). The rest
# are dedicated load balancers: updates, downloads, assets. OpenAI / ChatGPT names are resolved
# the same way. Answers that fall in a shared CDN (Cloudflare, CloudFront, Fastly) are NOT added:
# one such address serves thousands of unrelated sites. Those names are listed in the uncovered
# file instead. Deliberately not listed here either: a-cdn.claude.ai, *.mcp.claude.com,
# status.claude.com (CloudFront / shared front ends, static files and the status page).
LEARN_DOMAINS="api.anthropic.com claude.ai api.claude.ai claude.com platform.claude.com console.anthropic.com mcp-proxy.anthropic.com code.claude.com a.claude.ai a-api.anthropic.com assets-proxy.anthropic.com www.anthropic.com releases.claude.com downloads.claude.ai a-cdn.anthropic.com s-cdn.anthropic.com assets.claude.ai statsig.anthropic.com http-intake.logs.us5.datadoghq.com datadoghq.com o1158394.ingest.us.sentry.io api.openai.com chatgpt.com chat.openai.com auth.openai.com platform.openai.com cdn.oaistatic.com files.oaiusercontent.com oaiusercontent.com ab.chatgpt.com ios.chat.openai.com android.chat.openai.com claudeusercontent.com www.claudeusercontent.com claudemcpcontent.com www.claudemcpcontent.com"
EXTRA_DOMAINS=""
LEARN_INTERVAL=1800
LEARN_MAX_AGE=2592000
BLOCKED_COUNTRIES="RU BY"
COUNTRY_URLS="https://1.1.1.1/cdn-cgi/trace https://www.cloudflare.com/cdn-cgi/trace https://ipinfo.io/json"
COUNTRY_INTERVAL=30
COUNTRY_RETRY=5
COUNTRY_WAIT_MAX=8
COUNTRY_FAIL=open
TICK=5
LOG_MAX_BYTES=5000000

# The config is sourced as code by root, so it is read only if nobody else can change it: the
# file and every folder above it are owned by root (or by the current user, in the simulation)
# and not writable by group or others.
path_trusted() {
  local p="$1" me owner perm
  me=$(id -u)
  while :; do
    # macOS stat does not follow the link, but sourcing the config does. A link would hide
    # the real file from this check, so a symlink anywhere on the path is refused.
    [ -L "${p}" ] && return 1
    owner=$(stat -f %u "${p}" 2>/dev/null) || return 1
    perm=$(stat -f %Lp "${p}" 2>/dev/null) || return 1
    [ "${owner}" = 0 ] || [ "${owner}" = "${me}" ] || return 1
    [ $(( 8#${perm} & 022 )) = 0 ] || return 1
    [ "${p}" = / ] && return 0
    p=$(dirname "${p}")
  done
}
CONFIG_IGNORED=""
if [ -r "${CONFIG}" ]; then
  if path_trusted "${CONFIG}"; then
    # shellcheck disable=SC1090
    . "${CONFIG}"
  else
    CONFIG_IGNORED=1
  fi
fi
LEARN_DOMAINS="${LEARN_DOMAINS} ${EXTRA_DOMAINS:-}"

MODE_FILE="${STATE_DIR}/mode"
PIN_FILE="${STATE_DIR}/pinned"
COUNTRY_FILE="${STATE_DIR}/country"
COUNTER_FILE="${STATE_DIR}/counters"
LEARNED_FILE="${STATE_DIR}/learned"
UNCOVERED_FILE="${STATE_DIR}/uncovered"
NETS_FILE="${STATE_DIR}/nets"
TOKEN_FILE="${STATE_DIR}/pf_token"
NOTIFY_DIR="${STATE_DIR}/notified"

MODE=closed        # open | closed | country
PINNED_ID=""       # "<iface> <index> <generation> <addrs>" of the verified tunnel
PINNED_IF=""
LAST_COUNTRY=0
UNKNOWN_STREAK=0
VERDICT=""

# ------------------------------------------------------------------ plumbing

log() {
  local line
  line="$(date '+%Y-%m-%dT%H:%M:%S%z') $*"
  printf '%s\n' "${line}" >>"${LOG}" 2>/dev/null
  [ -n "${CVL_VERBOSE:-}" ] && printf '%s\n' "${line}" >&2
  return 0
}

rotate_log() {
  local size
  size=$(stat -f %z "${LOG}" 2>/dev/null || printf 0)
  [ "${size}" -gt "${LOG_MAX_BYTES}" ] 2>/dev/null && mv -f "${LOG}" "${LOG}.1"
  return 0
}

# The background learner writes counters too. Without the lock two read-modify-write cycles
# overlap and one update is lost (about half of 400 increments were lost; tests/sim.sh scenario 26).
# mkdir is atomic; bash 3.2 has no flock. Counters are diagnostics: after 1 s of waiting the lock
# is taken over, and callers update counters only after the pf work is done, so a lock left by a
# killed process never delays the rule. Daemon start removes a leftover lock.
counter_add() {
  local key="$1" add="${2:-1}" value=0 others tmp lock="${COUNTER_FILE}.lock" i
  for i in $(seq 1 20); do
    mkdir "${lock}" 2>/dev/null && break
    [ "${i}" = 20 ] && { rm -rf "${lock}"; mkdir "${lock}" 2>/dev/null; }
    sleep 0.05
  done
  tmp="${COUNTER_FILE}.tmp.${RANDOM}${RANDOM}"
  [ -f "${COUNTER_FILE}" ] && value=$(sed -n "s/^${key}=//p" "${COUNTER_FILE}" | head -1)
  case "${value}" in ''|*[!0-9]*) value=0 ;; esac
  others=$(grep -v "^${key}=" "${COUNTER_FILE}" 2>/dev/null || true)
  { [ -n "${others}" ] && printf '%s\n' "${others}"; printf '%s=%s\n' "${key}" "$((value + add))"; } \
    >"${tmp}" 2>/dev/null && mv -f "${tmp}" "${COUNTER_FILE}"
  rm -f "${tmp}" 2>/dev/null
  rmdir "${lock}" 2>/dev/null
  return 0
}
counter_bump() { counter_add "$1" 1; }

# Runs a command with a time limit; the watcher must not hold the caller's stdout open.
with_timeout() {
  local secs="$1" pid watcher rc
  shift
  "$@" &
  pid=$!
  ( sleep "${secs}"; kill "${pid}" 2>/dev/null ) >/dev/null 2>&1 &
  watcher=$!
  wait "${pid}" 2>/dev/null
  rc=$?
  kill "${watcher}" 2>/dev/null
  wait "${watcher}" 2>/dev/null
  return "${rc}"
}

# A desktop notification for the person at the console, at most once per key per 10 minutes.
notify() {
  local key="$1" text="$2" uid stamp now
  [ -n "${CVL_NO_NOTIFY:-}" ] && return 0
  mkdir -p "${NOTIFY_DIR}" 2>/dev/null
  stamp="${NOTIFY_DIR}/${key}"
  now=$(date +%s)
  if [ -f "${stamp}" ] && [ $((now - $(stat -f %m "${stamp}" 2>/dev/null || printf 0))) -lt 600 ]; then
    return 0
  fi
  touch "${stamp}" 2>/dev/null
  uid=$(stat -f %u /dev/console 2>/dev/null)
  [ -n "${uid}" ] && [ "${uid}" != 0 ] || return 0
  launchctl asuser "${uid}" /usr/bin/osascript \
    -e "display notification \"${text}\" with title \"network-kill-switch\"" >/dev/null 2>&1 &
  return 0
}

# ------------------------------------------------------------------ network facts

route_iface() {
  "${ROUTE}" -n get "${ROUTE_PROBE}" 2>/dev/null | awk '/interface:/ {print $2; exit}'
}

is_vpn_name() {
  case "$1" in utun*|ipsec*|ppp*|tun*|tap*) return 0 ;; *) return 1 ;; esac
}

# "<iface> <index> <generation> <addr>[,<addr>]" of the VPN interface that carries the route
# to Anthropic right now. Status 1 when that route is not a VPN tunnel with an address.
# The kernel marks interfaces owned by a VPN (NetworkExtension) with xflag IS_VPN; a system
# utun (iCloud, Continuity) or a bare ppp link without it never counts as a tunnel.
# index + generation change when the interface is re-created, even under the same name.
tunnel_identity() {
  local ifc
  ifc=$(route_iface)
  [ -n "${ifc}" ] || return 1
  is_vpn_name "${ifc}" || return 1
  "${IFCONFIG}" -v "${ifc}" 2>/dev/null | awk -v ifc="${ifc}" '
    NR == 1 { for (i = 1; i <= NF; i++) if ($i == "index") idx = $(i + 1) }
    /xflags=.*IS_VPN/ || /agent domain:NetworkExtension type:VPN/ { vpn = 1 }
    /generation id:/ { gen = $NF }
    /^[ \t]+inet / { addrs = addrs (addrs != "" ? "," : "") $2 }
    /^[ \t]+inet6 / {
      a = $2; sub(/%.*$/, "", a)
      if (a !~ /^fe80/) addrs = addrs (addrs != "" ? "," : "") a
    }
    END {
      if (addrs == "" || !vpn) exit 1
      print ifc, (idx == "" ? "-" : idx), (gen == "" ? "-" : gen), addrs
    }'
}

# "<iface> <index> <generation>": the interface instance, without its addresses.
instance_of() { printf '%s\n' "$1" | awk '{ print $1, $2, $3 }'; }

first_addr() { printf '%s\n' "$1" | awk '{ split($4, a, ","); print a[1] }'; }

# Address of the physical interface behind the non-VPN default route (diagnostics only).
direct_addr() {
  local ifc
  ifc=$("${NETSTAT}" -rn -f inet 2>/dev/null \
        | awk '$1 == "default" && $NF !~ /^(utun|ipsec|ppp|tun|tap)/ { print $NF; exit }')
  [ -n "${ifc}" ] || return 1
  "${IFCONFIG}" "${ifc}" 2>/dev/null | awk '/[ \t]inet / { print $2; exit }'
}

# ------------------------------------------------------------------ pf

pf_enabled() { "${PFCTL}" -s info 2>/dev/null | grep -q 'Status: Enabled'; }

main_has_apple_anchor() { "${PFCTL}" -s rules 2>/dev/null | grep -q '^anchor "com.apple/\*"'; }

anchor_rule() { "${PFCTL}" -a "${ANCHOR}" -s rules 2>/dev/null | head -1; }

# Packets matched by the anchor's rule since it was loaded.
rule_packets() {
  "${PFCTL}" -a "${ANCHOR}" -v -s rules 2>/dev/null | awk '
    /Packets:/ { for (i = 1; i <= NF; i++) if ($i == "Packets:") s += $(i + 1) }
    END { print s + 0 }'
}

# pf is reference-counted on macOS: -E takes a reference and prints a token, -X releases it.
# Holding our own reference means another component releasing its own cannot switch pf off.
pf_take_ref() {
  local old out token
  old=$(cat "${TOKEN_FILE}" 2>/dev/null)
  if [ -n "${old}" ] && pf_enabled && "${PFCTL}" -s References 2>/dev/null | grep -q "${old}"; then
    return 0
  fi
  out=$("${PFCTL}" -E 2>&1)
  token=$(printf '%s\n' "${out}" | sed -n 's/^Token : *//p' | head -1)
  if [ -n "${token}" ]; then
    printf '%s\n' "${token}" >"${TOKEN_FILE}"
    log "PF enabled, our reference token ${token}"
    if [ -n "${old}" ] && [ "${old}" != "${token}" ]; then
      "${PFCTL}" -X "${old}" >/dev/null 2>&1
    fi
  else
    log "ERROR pfctl -E returned no token: $(printf '%s' "${out}" | tr '\n' ' ' | cut -c1-200)"
    counter_bump pf_enable_failed
  fi
  return 0
}

# A dotted quad with each octet in 0..255. Hostnames, including a CNAME from `dig +short`, fail.
valid_ip4() {
  local a b c d o
  case "$1" in
    *.*.*.*) ;;
    *) return 1 ;;
  esac
  case "$1" in
    *.*.*.*.*) return 1 ;;
  esac
  IFS=. read -r a b c d <<EOF
$1
EOF
  for o in "$a" "$b" "$c" "$d"; do
    case "$o" in
      [0-9]|[1-9][0-9]|[1-9][0-9][0-9]) [ "$o" -le 255 ] || return 1 ;;
      *) return 1 ;;
    esac
  done
  return 0
}

# Hex and colons only, one compression, eight groups when written out in full.
valid_ip6() {
  local s="$1" t part parts=0 compressed=0
  [ "$s" = :: ] && return 0
  case "$s" in
    *[!0-9A-Fa-f:]*) return 1 ;;
    *:::*) return 1 ;;
    :[!:]*) return 1 ;;
    *[!]:) return 1 ;;
  esac
  case "$s" in
    *::*)
      case "${s#*::}" in *::*) return 1 ;; esac
      compressed=1
      t=${s/::/:_:}
      ;;
    *) t=$s ;;
  esac
  local IFS=:
  for part in ${t}; do
    [ "${part}" = _ ] && continue
    [ -n "${part}" ] || return 1
    [ "${#part}" -le 4 ] || return 1
    case "${part}" in *[!0-9A-Fa-f]*) return 1 ;; esac
    parts=$((parts + 1))
  done
  if [ "${compressed}" = 1 ]; then
    [ "${parts}" -le 7 ]
    return
  fi
  [ "${parts}" -eq 8 ]
}

# Public unicast addresses only; private, CGNAT, fake-IP, loopback, multicast and NAT64 never enter.
valid_public() {
  if valid_ip4 "$1"; then
    case "$1" in
      0.*|10.*|127.*|169.254.*|192.168.*|198.18.*|198.19.*|255.*) return 1 ;;
      172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 1 ;;
      100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 1 ;;
      22[4-9].*|23[0-9].*|24[0-9].*|25[0-4].*) return 1 ;;
    esac
    return 0
  fi
  valid_ip6 "$1" || return 1
  case "$1" in
    ::|::1|[fF][eE][89aAbB]*|[fF][cCdD]*|[fF][fF]*|::ffff:*|64:[fF][fF]9[bB]:*) return 1 ;;
  esac
  return 0
}

# IPv4 only. Shared anycast blocks: one address here belongs to thousands of other sites.
# 3.164.0.0-3.175.255.255 are published CloudFront ranges past the older 3.160.0.0/14 sample.
# datadoghq.com currently answers from 3.168.0.0/14.
SHARED_V4="173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 13.32.0.0/15 13.224.0.0/14 13.249.0.0/16 52.84.0.0/15 54.182.0.0/16 54.192.0.0/16 54.230.0.0/16 54.239.128.0/18 99.84.0.0/16 205.251.192.0/19 204.246.164.0/22 64.252.64.0/18 70.132.0.0/18 3.160.0.0/14 3.164.0.0/18 3.164.64.0/18 3.164.128.0/17 3.165.0.0/16 3.166.0.0/15 3.168.0.0/14 3.172.0.0/18 3.172.64.0/18 3.173.0.0/17 3.173.128.0/18 3.173.192.0/18 3.174.0.0/15 15.158.0.0/16 65.8.0.0/16 65.9.0.0/16 71.152.0.0/17 18.64.0.0/14 18.154.0.0/16 18.238.0.0/15 120.52.22.96/27 130.176.0.0/16 143.204.0.0/16 23.235.32.0/20 43.249.72.0/22 103.244.50.0/24 103.245.222.0/23 103.245.224.0/24 104.156.80.0/20 140.248.64.0/18 140.248.128.0/17 146.75.0.0/17 151.101.0.0/16 157.52.64.0/18 167.82.0.0/17 167.82.128.0/20 167.82.160.0/20 167.82.224.0/20 172.111.64.0/18 185.31.16.0/22 199.27.72.0/21 199.232.0.0/16"

ip4_to_int() {
  local a b c d
  IFS=. read -r a b c d <<EOF
$1
EOF
  printf '%s\n' $(( (a * 16777216) + (b * 65536) + (c * 256) + d ))
}

ip4_in_cidr() {
  local ipi net bits base mask
  ipi=$(ip4_to_int "$1")
  base=${2%/*}
  bits=${2#*/}
  net=$(ip4_to_int "${base}")
  mask=$(( (4294967295 << (32 - bits)) & 4294967295 ))
  [ $(( ipi & mask )) -eq $(( net & mask )) ]
}

# Status 0 when this address must not enter the block table.
shared_cdn() {
  local c
  case "$1" in
    # Cloudflare (2a06:98c0::/29), CloudFront (2600:9000::/32 and the 2600:f0f0 samples), Fastly.
    2606:4700:*|2400:cb00:*|2803:f800:*|2405:b500:*|2405:8100:*|2a06:98c[0-7]:*|2c0f:f248:*|2600:9000:*|2600:f0f0:5504:*|2600:f0f0:601:*|2600:f0f0:602:*|2600:f0f0:603:*|2a04:4e40:*|2a04:4e42:*) return 0 ;;
    *:*) return 1 ;;
  esac
  valid_ip4 "$1" || return 1
  for c in ${SHARED_V4}; do
    ip4_in_cidr "$1" "${c}" && return 0
  done
  return 1
}

# What this Mac's resolver currently says, plus a direct lookup when dig is available.
resolve_host() {
  local host="$1"
  with_timeout 5 "${DSCACHEUTIL}" -q host -a name "${host}" 2>/dev/null \
    | awk '/^ip(v6)?_address:/ { print $2 }'
  if [ -n "${DIG_BIN}" ]; then
    with_timeout 5 "${DIG_BIN}" +time=2 +tries=1 +short A "${host}" 2>/dev/null
    with_timeout 5 "${DIG_BIN}" +time=2 +tries=1 +short AAAA "${host}" 2>/dev/null
  fi
}

learned_addrs() {
  [ -f "${LEARNED_FILE}" ] && awk 'NF { print $1 }' "${LEARNED_FILE}"
  return 0
}

nets_list() {
  { for n in ${PINNED_NETS} ${CANARY_NET}; do printf '%s\n' "${n}"; done; learned_addrs; } \
    | awk 'NF && !seen[$1]++'
}

# $1 = closed | <interface name>
anchor_text() {
  local nets
  nets=$(nets_list | paste -s -d, - | sed 's/,/, /g')
  printf 'table <nks_nets> persist { %s }\n' "${nets}"
  if [ "$1" = closed ]; then
    printf 'block return out quick to <nks_nets> label "nks-closed"\n'
  else
    printf 'block return out quick on ! %s to <nks_nets> label "nks-offtunnel"\n' "$1"
  fi
}

load_rules() {
  local prev out
  prev=$(rule_packets)
  if out=$(anchor_text "$1" | "${PFCTL}" -a "${ANCHOR}" -f - 2>&1); then
    if [ "${prev:-0}" -gt 0 ] 2>/dev/null; then
      log "PF rule being replaced had blocked ${prev} packets"
      counter_add blocked_packets "${prev}"
    fi
    return 0
  fi
  log "ERROR loading anchor (${1}): $(printf '%s' "${out}" | tr '\n' ' ' | cut -c1-300)"
  counter_bump pf_load_failed
  return 1
}

# The table must hold every network the daemon means to block (someone may flush only the table).
table_matches() {
  local want have
  want=$(nets_list | awk 'NF { print $1 }' | sort -u)
  have=$("${PFCTL}" -a "${ANCHOR}" -t nks_nets -T show 2>/dev/null | awk 'NF { print $1 }' | sort -u)
  [ "${want}" = "${have}" ]
}

rule_matches_mode() {
  local rule
  rule=$(anchor_rule)
  if [ "${MODE}" = open ]; then
    case "${rule}" in *"on ! ${PINNED_IF} "*nks-offtunnel*) return 0 ;; esac
  else
    case "${rule}" in *nks-closed*) return 0 ;; esac
  fi
  return 1
}

# ------------------------------------------------------------------ learning

# Merge freshly resolved rows into the learned file and drop entries older than LEARN_MAX_AGE.
# An empty incoming set still ages the file: a resolver that keeps failing must not pin an
# address forever.
write_learned() {
  local now="$1" incoming="$2"
  {
    [ -f "${LEARNED_FILE}" ] && cat "${LEARNED_FILE}"
    [ -n "${incoming}" ] && printf '%s\n' "${incoming}"
    true
  } \
    | awk -v now="${now}" -v maxage="${LEARN_MAX_AGE}" '
        NF >= 2 { if (!($1 in t) || $2 > t[$1]) { t[$1] = $2; h[$1] = $3 } }
        END { for (ip in t) if (now - t[ip] <= maxage) print ip, t[ip], h[ip] }' \
    | while read -r ip ts host; do
        [ -n "${ip}" ] || continue
        valid_public "${ip}" || continue
        shared_cdn "${ip}" && continue
        printf '%s %s %s\n' "${ip}" "${ts}" "${host}"
      done \
    | sort >"${LEARNED_FILE}.tmp" && mv -f "${LEARNED_FILE}.tmp" "${LEARNED_FILE}"
}

refresh_table_if_needed() {
  nets_list >"${NETS_FILE}.new"
  if ! cmp -s "${NETS_FILE}.new" "${NETS_FILE}" 2>/dev/null; then
    if "${PFCTL}" -a "${ANCHOR}" -t nks_nets -T replace -f "${NETS_FILE}.new" >/dev/null 2>&1; then
      mv -f "${NETS_FILE}.new" "${NETS_FILE}"
      log "LEARN table nks_nets = $(tr '\n' ' ' <"${NETS_FILE}")"
    else
      counter_bump learn_table_failed
      log "WARN could not update table nks_nets"
    fi
  fi
  rm -f "${NETS_FILE}.new"
}

learn() {
  local now raw found skipped mine
  now=$(date +%s)
  raw=$(
    for host in ${LEARN_DOMAINS}; do
      kept=0
      cdn=0
      mine=$(awk -v name="${host}" 'NF && $1 !~ /^#/ {
          for (i = 2; i <= NF; i++) if (tolower($i) == tolower(name)) { print $1; break }
        }' "${ETC_HOSTS}" 2>/dev/null)
      while read -r ip; do
        [ -n "${ip}" ] || continue
        valid_public "${ip}" || continue
        if shared_cdn "${ip}"; then
          cdn=1
          continue
        fi
        # an /etc/hosts line for this exact name (e.g. a relay) is not where the service lives
        printf '%s\n' "${mine}" | grep -qxF "${ip}" && continue
        kept=1
        printf 'IP %s %s %s\n' "${ip}" "${now}" "${host}"
      done <<EOF
$(resolve_host "${host}")
EOF
      if [ "${cdn}" = 1 ]; then
        printf 'SKIP %s\n' "${host}"
      fi
    done)
  found=$(printf '%s\n' "${raw}" | awk '/^IP / { print $2, $3, $4 }')
  skipped=$(printf '%s\n' "${raw}" | awk '/^SKIP / { print $2 }')
  if [ -z "${found}" ]; then
    counter_bump learn_empty
    log "WARN learning found no dedicated addresses; the previous list is kept and aged"
  fi
  write_learned "${now}" "${found}"
  if [ -n "${skipped}" ]; then
    printf '%s\n' "${skipped}" | sort -u >"${UNCOVERED_FILE}"
    log "LEARN shared CDN, not blocked: $(tr '\n' ' ' <"${UNCOVERED_FILE}")"
  elif [ -n "${found}" ]; then
    rm -f "${UNCOVERED_FILE}"
  fi
  if [ -n "$(anchor_rule)" ]; then
    refresh_table_if_needed
  fi
  return 0
}

# ------------------------------------------------------------------ exit country

# $1 = source address (the tunnel's), $2 = seconds left. Prints "<CC> <exit ip>".
# Understands Cloudflare's trace (loc=/ip=) and ipinfo-style JSON ("country"/"ip").
country_lookup() {
  local url body cc ip left t deadline first=1
  deadline=$(( $(date +%s) + $2 ))
  for url in ${COUNTRY_URLS}; do
    left=$(( deadline - $(date +%s) ))
    # The clock is read in whole seconds: a second boundary right after the deadline was set
    # must not cancel the first attempt (seen under load as "unknown" with nothing tried).
    [ "${first}" = 1 ] && [ "${left}" -lt 1 ] && left=1
    first=0
    [ "${left}" -ge 1 ] || return 1
    t=3
    [ "${left}" -lt 3 ] && t=${left}
    body=$("${CURL}" -s -m "${t}" --interface "$1" -A network-kill-switch "${url}" 2>/dev/null) || body=""
    cc=$(printf '%s\n' "${body}" | sed -n -e 's/^loc=\([A-Za-z][A-Za-z]\)$/\1/p' \
           -e 's/.*"country"[ ]*:[ ]*"\([A-Za-z][A-Za-z]\)".*/\1/p' | head -1)
    ip=$(printf '%s\n' "${body}" | sed -n -e 's/^ip=//p' \
           -e 's/.*"ip"[ ]*:[ ]*"\([0-9a-fA-F:.]*\)".*/\1/p' | head -1)
    if [ -n "${cc}" ]; then
      printf '%s %s\n' "$(printf '%s' "${cc}" | tr 'a-z' 'A-Z')" "${ip:-?}"
      return 0
    fi
  done
  return 1
}

is_blocked_cc() {
  local c
  for c in ${BLOCKED_COUNTRIES}; do [ "$1" = "${c}" ] && return 0; done
  return 1
}

# Status 0 = exit allowed, 1 = exit country blocked, 2 = unknown. Sets VERDICT.
# Hard limit COUNTRY_WAIT_MAX seconds in total: the event loop waits for it.
check_exit() {
  local deadline res cc ip left first=1
  deadline=$(( $(date +%s) + COUNTRY_WAIT_MAX ))
  while :; do
    left=$(( deadline - $(date +%s) ))
    [ "${first}" = 1 ] && [ "${left}" -lt 1 ] && left=1   # at least one attempt, see country_lookup
    first=0
    [ "${left}" -ge 1 ] || break
    if res=$(country_lookup "$1" "${left}"); then
      cc=${res%% *}
      ip=${res#* }
      printf 'at=%s\ncc=%s\nip=%s\n' "$(date +%s)" "${cc}" "${ip}" >"${COUNTRY_FILE}"
      VERDICT="exit ${cc} ${ip}"
      is_blocked_cc "${cc}" && return 1
      return 0
    fi
    [ $(( deadline - $(date +%s) )) -ge 2 ] || break
    sleep 1
  done
  printf 'at=%s\ncc=?\nip=?\n' "$(date +%s)" >"${COUNTRY_FILE}"
  VERDICT="exit country unknown"
  return 2
}

# Why the exit is in a blocked country: the VPN app routed past its tunnel, or the server is there.
explain_blocked_exit() {
  local exit_ip="$1" addr home
  addr=$(direct_addr) || addr=""
  [ -n "${addr}" ] || return 0
  home=$("${CURL}" -s -m 3 --interface "${addr}" https://1.1.1.1/cdn-cgi/trace 2>/dev/null | sed -n 's/^ip=//p' | head -1)
  if [ -n "${home}" ] && [ "${home}" = "${exit_ip}" ]; then
    printf ' (the VPN app sends flows past its tunnel: exit = this network'"'"'s own address)'
    counter_bump vpn_bypass_seen
  elif [ -n "${home}" ]; then
    printf ' (VPN server in a blocked country)'
  fi
}

# ------------------------------------------------------------------ state machine

# Existing pf states are checked before filter rules and are not tied to an interface.
# Dropping them when the block becomes total, or when the trusted interface name changes,
# stops a connection that was allowed on the old path from continuing on the new one.
drop_protected_states() {
  local n
  for n in $(nets_list); do
    case "${n}" in
      *:*) "${PFCTL}" -k ::/0 -k "${n}" >/dev/null 2>&1 || true ;;
      *) "${PFCTL}" -k 0.0.0.0/0 -k "${n}" >/dev/null 2>&1 || true ;;
    esac
  done
  log "pf states to watched nets dropped"
  return 0
}

apply() {   # $1 mode  $2 closed|<iface>  $3 identity  $4 reason
  local prev_if="${PINNED_IF}"
  if load_rules "$2"; then
    MODE="$1"
    PINNED_ID="$3"
  else
    load_rules closed
    MODE=closed
    PINNED_ID=""
    notify load_failed "pf rules could not be loaded, see /var/log/network-kill-switch.log"
  fi
  PINNED_IF=""
  [ "${MODE}" = open ] && PINNED_IF="${PINNED_ID%% *}"
  if [ "${MODE}" != open ] || [ "${PINNED_IF}" != "${prev_if}" ]; then
    drop_protected_states
  fi
  printf '%s\n' "${MODE}" >"${MODE_FILE}"
  printf '%s\n' "${PINNED_ID}" >"${PIN_FILE}"
  log "STATE ${MODE} :: $4"
  counter_bump "state_${MODE}"
  return 0
}

set_open() {
  if [ "${MODE}" = open ] && [ "${PINNED_IF}" = "${1%% *}" ] && rule_matches_mode; then
    PINNED_ID="$1"   # same interface, rule already right: no reload, no cut connections
    printf '%s\n' "${PINNED_ID}" >"${PIN_FILE}"
    log "STATE open :: $2 (same interface, rule kept)"
    return 0
  fi
  apply open "${1%% *}" "$1" "$2"
}
set_country() { apply country closed "$1" "$2"; }
set_closed()  { apply closed closed "" "$1"; }

verify_and_apply() {   # $1 identity  $2 why
  local src rc extra
  src=$(first_addr "$1")
  check_exit "${src}"
  rc=$?
  LAST_COUNTRY=$(date +%s)
  case "${rc}" in
    0)
      UNKNOWN_STREAK=0
      if [ "${MODE}" != open ] || [ "${PINNED_ID}" != "$1" ]; then
        set_open "$1" "$2; ${VERDICT}"
      fi
      ;;
    1)
      UNKNOWN_STREAK=0
      if [ "${MODE}" != country ] || [ "${PINNED_ID}" != "$1" ]; then
        # Close first. The explanation is a second lookup and must not delay the block.
        set_country "$1" "$2; ${VERDICT}"
        extra=$(explain_blocked_exit "${VERDICT##* }")
        [ -n "${extra}" ] && log "STATE country :: ${VERDICT}${extra}"
        notify country "Claude blocked: VPN exit is ${VERDICT#exit }"
      fi
      ;;
    *)
      counter_bump country_unknown
      UNKNOWN_STREAK=$((UNKNOWN_STREAK + 1))
      if [ "${PINNED_ID}" != "$1" ]; then
        # A tunnel with no verdict yet. Unknown is never a reason to leave a known state.
        if [ "${COUNTRY_FAIL}" = open ]; then
          counter_bump country_unknown_opened
          set_open "$1" "$2; ${VERDICT}, opened by COUNTRY_FAIL=open"
        elif [ "${MODE}" != closed ] || [ -n "${PINNED_ID}" ]; then
          set_closed "$2; ${VERDICT}, kept closed by COUNTRY_FAIL=closed"
        fi
      elif [ "${COUNTRY_FAIL}" = closed ] && [ "${MODE}" = open ] \
           && [ "${UNKNOWN_STREAK}" -ge "${COUNTRY_RETRY}" ]; then
        set_closed "$2; ${VERDICT}, closed after ${UNKNOWN_STREAK} unknown checks"
      elif [ $((UNKNOWN_STREAK % 20)) -eq 1 ]; then
        log "WARN ${VERDICT} (streak ${UNKNOWN_STREAK}); state ${MODE} kept"
      fi
      ;;
  esac
  return 0
}

evaluate() {   # $1 = trigger
  local id now
  id=$(tunnel_identity) || id=""
  now=$(date +%s)
  if [ -z "${id}" ]; then
    if [ "${MODE}" != closed ] || [ -n "${PINNED_ID}" ]; then
      set_closed "$1: no VPN tunnel carries the route to Anthropic (via $(route_iface))"
    fi
    return 0
  fi
  if [ "${id}" != "${PINNED_ID}" ]; then
    # A tunnel we have not verified. Under a new name the pinned rule already blocks it;
    # under the pinned name it would pass, so close before checking.
    if [ "${MODE}" = open ] && [ "${id%% *}" = "${PINNED_IF}" ] \
       && [ "$(instance_of "${id}")" != "$(instance_of "${PINNED_ID}")" ]; then
      set_closed "$1: tunnel ${PINNED_IF} was re-created (${PINNED_ID} -> ${id})"
    fi
    verify_and_apply "${id}" "$1: tunnel ${id}"
    return 0
  fi
  case "${MODE}" in
    open)
      [ $((now - LAST_COUNTRY)) -ge "${COUNTRY_INTERVAL}" ] && verify_and_apply "${id}" "$1: periodic check"
      ;;
    *)
      [ $((now - LAST_COUNTRY)) -ge "${COUNTRY_RETRY}" ] && verify_and_apply "${id}" "$1: re-check"
      ;;
  esac
  return 0
}

heal() {
  if ! pf_enabled; then
    log "WARN pf was switched off by someone; switching it on"
    pf_take_ref
    counter_bump pf_reenabled
    notify pf_off "pf was switched off; network-kill-switch switched it back on"
  fi
  if ! rule_matches_mode; then
    log "WARN anchor ${ANCHOR} lost its rule (now: '$(anchor_rule)'); re-loading"
    if [ "${MODE}" = open ]; then load_rules "${PINNED_IF}" || load_rules closed; else load_rules closed; fi
    counter_bump anchor_healed
  fi
  if ! table_matches; then
    log "WARN table nks_nets lost entries ($("${PFCTL}" -a "${ANCHOR}" -t nks_nets -T show 2>/dev/null | grep -c .) of $(nets_list | grep -c .)); re-filling"
    nets_list >"${NETS_FILE}"
    "${PFCTL}" -a "${ANCHOR}" -t nks_nets -T replace -f "${NETS_FILE}" >/dev/null 2>&1 \
      || { log "ERROR cannot re-fill table nks_nets"; counter_bump table_heal_failed; }
    counter_bump table_healed
  fi
  return 0
}

check_main_anchor() {
  main_has_apple_anchor && return 0
  log "ERROR the main pf ruleset no longer has anchor \"com.apple/*\"; the rule is not evaluated"
  counter_bump main_anchor_missing
  notify main_anchor "PROTECTION OFF: pf main ruleset was replaced. Run: sudo pfctl -f /etc/pf.conf"
  return 1
}

restore_or_close() {
  local saved_mode saved_pin cur
  saved_mode=$(cat "${MODE_FILE}" 2>/dev/null)
  saved_pin=$(cat "${PIN_FILE}" 2>/dev/null)
  cur=$(tunnel_identity) || cur=""
  if [ "${saved_mode}" = open ] && [ -n "${saved_pin}" ] && [ "${saved_pin}" = "${cur}" ]; then
    MODE=open
    PINNED_ID="${saved_pin}"
    PINNED_IF="${saved_pin%% *}"
    if rule_matches_mode; then
      LAST_COUNTRY=0   # verify again on the first evaluation, without closing first
      log "RESTORE kept the open rule for ${saved_pin}"
      return 0
    fi
  fi
  MODE=closed
  PINNED_ID=""
  PINNED_IF=""
  set_closed "start: closed until a tunnel is verified"
}

# Interface events come from `route -n monitor` through a FIFO on fd 3 (not stdin, so nothing
# called inside the loop can swallow them). bash 3.2 returns 1 from `read -t` both on timeout
# and at end of stream, so the end of stream is told apart by the monitor's PID being gone.
MON_PID=""
MON_FIFO="${STATE_DIR}/route-events.fifo"

start_monitor() {
  rm -f "${MON_FIFO}"
  mkfifo -m 600 "${MON_FIFO}" || return 1
  "${ROUTE}" -n monitor >"${MON_FIFO}" 2>/dev/null &
  MON_PID=$!
  exec 3<"${MON_FIFO}"
}

stop_monitor() {
  exec 3<&- 2>/dev/null
  if [ -n "${MON_PID}" ]; then
    kill "${MON_PID}" 2>/dev/null
    wait "${MON_PID}" 2>/dev/null
  fi
  MON_PID=""
  rm -f "${MON_FIFO}"
}

LAST_TICK=0
LAST_LEARN=0
LEARN_PID=""
TICKS=0

# One learning pass at a time, off the decisions that open and close the rule.
kick_learn() {
  if [ -n "${LEARN_PID}" ] && kill -0 "${LEARN_PID}" 2>/dev/null; then
    return 0
  fi
  LAST_LEARN=$(date +%s)
  learn &
  LEARN_PID=$!
  return 0
}

stop_learn() {
  if [ -n "${LEARN_PID}" ]; then
    kill "${LEARN_PID}" 2>/dev/null
    wait "${LEARN_PID}" 2>/dev/null
  fi
  LEARN_PID=""
  return 0
}

# Housekeeping every TICK seconds, whatever the event source is doing.
maybe_tick() {
  local now
  now=$(date +%s)
  [ $((now - LAST_TICK)) -ge "${TICK}" ] || return 0
  LAST_TICK=${now}
  TICKS=$((TICKS + 1))
  heal
  evaluate tick
  [ $((TICKS % 12)) -eq 0 ] && check_main_anchor
  if [ $((now - LAST_LEARN)) -ge "${LEARN_INTERVAL}" ]; then
    kick_learn
  fi
  [ $((TICKS % 120)) -eq 0 ] && rotate_log
  return 0
}

cmd_run() {
  local line started fast_fails=0 backoff resume_at
  mkdir -p "${STATE_DIR}" 2>/dev/null
  touch "${LOG}" 2>/dev/null
  trap 'stop_learn; stop_monitor; log "STOP pid=$$"; exit 0' TERM INT
  rm -rf "${COUNTER_FILE}.lock"   # left by a killed predecessor; nothing else writes yet
  log "START network-kill-switch ${VERSION} pid=$$ anchor=${ANCHOR}"
  [ -n "${CONFIG_IGNORED}" ] && log "WARN config ${CONFIG} ignored: it or a folder above it can be changed by a non-root user"
  pf_take_ref
  restore_or_close
  check_main_anchor
  heal
  evaluate start
  kick_learn
  while :; do
    started=$(date +%s)
    if start_monitor; then
      while :; do
        if IFS= read -r -t "${TICK}" -u 3 line; then
          case "${line}" in
            RTM_IFINFO*|RTM_NEWADDR*|RTM_DELADDR*|RTM_IFINFO2*) evaluate event ;;
          esac
        elif ! kill -0 "${MON_PID}" 2>/dev/null; then
          break   # route monitor exited
        fi
        maybe_tick
      done
      stop_monitor
    fi
    # No event source: keep ticking (the lock must not stop) and retry the monitor,
    # at once after a long run, after a minute when it keeps dying right away.
    if [ $(( $(date +%s) - started )) -lt 5 ]; then fast_fails=$((fast_fails + 1)); else fast_fails=0; fi
    counter_bump monitor_restart
    backoff=1
    [ "${fast_fails}" -ge 2 ] && backoff=60
    [ "${fast_fails}" -le 2 ] && log "WARN route monitor ended; polling every ${TICK} s, retry in ${backoff} s"
    resume_at=$(( $(date +%s) + backoff ))
    while [ "$(date +%s)" -lt "${resume_at}" ]; do
      sleep 1
      maybe_tick
    done
  done
}

# Used by the installer. On a fresh anchor it checks the exit first and loads the open rule
# directly, so installing does not cut the connections of a Claude session that is running
# through a good tunnel. Without a verified tunnel it loads the closed rule.
cmd_once() {
  mkdir -p "${STATE_DIR}" 2>/dev/null
  rm -rf "${COUNTER_FILE}.lock"
  log "ONCE network-kill-switch ${VERSION}"
  [ -n "${CONFIG_IGNORED}" ] && log "WARN config ${CONFIG} ignored: it or a folder above it can be changed by a non-root user"
  pf_take_ref
  learn
  if [ -z "$(anchor_rule)" ]; then
    MODE=closed
    PINNED_ID=""
    evaluate once
    [ -z "$(anchor_rule)" ] && set_closed "once: no verified tunnel"
  else
    restore_or_close
    evaluate once
  fi
  printf 'mode=%s pinned=%s\n' "${MODE}" "${PINNED_ID}"
}

cmd_status() {
  local age at
  at=$(sed -n 's/^at=//p' "${COUNTRY_FILE}" 2>/dev/null)
  age="?"
  [ -n "${at}" ] && age="$(( $(date +%s) - at )) s ago"
  printf 'version      : %s\n' "${VERSION}"
  printf 'config       : %s%s\n' "${CONFIG}" "$([ -n "${CONFIG_IGNORED}" ] && printf ' (IGNORED: can be changed by a non-root user)')"
  printf 'mode         : %s\n' "$(cat "${MODE_FILE}" 2>/dev/null || printf unknown)"
  printf 'pinned       : %s\n' "$(cat "${PIN_FILE}" 2>/dev/null)"
  printf 'route_iface  : %s (route to %s)\n' "$(route_iface)" "${ROUTE_PROBE}"
  printf 'tunnel_now   : %s\n' "$(tunnel_identity || printf none)"
  printf 'exit_check   : %s(%s)\n' "$(grep -v '^at=' "${COUNTRY_FILE}" 2>/dev/null | tr '\n' ' ')" "${age}"
  printf 'pf_enabled   : %s\n' "$(pf_enabled && printf yes || printf no)"
  printf 'pf_token     : %s\n' "$(cat "${TOKEN_FILE}" 2>/dev/null)"
  printf 'main_anchor  : %s\n' "$(main_has_apple_anchor && printf 'com.apple/* present' || printf MISSING)"
  printf 'rule         : %s\n' "$(anchor_rule)"
  printf 'rule_packets : %s\n' "$(rule_packets)"
  printf 'nets         : %s\n' "$("${PFCTL}" -a "${ANCHOR}" -t nks_nets -T show 2>/dev/null | tr -s ' \n' ' ')"
  printf 'uncovered    : %s\n' "$(tr '\n' ' ' <"${UNCOVERED_FILE}" 2>/dev/null)"
  printf 'counters     : %s\n' "$(tr '\n' ' ' <"${COUNTER_FILE}" 2>/dev/null)"
  return 0
}

# Proves the loaded rule with the canary address, never with Anthropic itself.
cmd_verify() {
  local fails=0 untested=0 addr before after rc
  printf 'rule: %s\n' "$(anchor_rule)"
  if ! main_has_apple_anchor; then
    printf 'FAIL main ruleset has no anchor "com.apple/*"\n'
    fails=$((fails + 1))
  fi
  pf_enabled || { printf 'FAIL pf is disabled\n'; fails=$((fails + 1)); }
  addr=$(direct_addr) || addr=""
  if [ -z "${addr}" ]; then
    printf 'NOT TESTED no physical interface address: the canary was not sent\n'
    untested=1
  else
    before=$(rule_packets)
    "${CURL}" -s -o /dev/null -m 3 --interface "${addr}" "http://${CANARY_NET}/" 2>/dev/null
    rc=$?
    after=$(rule_packets)
    printf 'canary from %s: curl exit %s, rule packets %s -> %s\n' "${addr}" "${rc}" "${before}" "${after}"
    if [ "${after}" -gt "${before}" ] 2>/dev/null; then
      printf 'OK the kernel dropped a packet that tried to leave past the tunnel\n'
    else
      printf 'FAIL the packet from the physical interface was not matched\n'
      fails=$((fails + 1))
    fi
  fi
  [ "${fails}" -eq 0 ] && [ "${untested}" = 1 ] && { printf 'VERIFY NOT TESTED\n'; return 2; }
  [ "${fails}" -eq 0 ] && { printf 'VERIFY OK\n'; return 0; }
  printf 'VERIFY FAILED (%s)\n' "${fails}"
  return 1
}

[ -n "${CVL_LIB:-}" ] && return 0

case "${1:-run}" in
  run) cmd_run ;;
  once) cmd_once ;;
  status) cmd_status ;;
  verify) cmd_verify ;;
  learn) mkdir -p "${STATE_DIR}"; learn ;;
  version) printf 'network-kill-switch %s (pf, interface-pinned)\n' "${VERSION}" ;;
  *) printf 'usage: %s {run|once|status|verify|learn|version}\n' "$0" >&2; exit 2 ;;
esac
