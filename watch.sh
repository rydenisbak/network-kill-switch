#!/bin/bash
# network-kill-switch: hourly check that the lock is actually enforcing.
#
#   sudo bash watch.sh            # one check; Telegram only when it is not
#   sudo bash watch.sh --install  # LaunchDaemon: at boot and every hour
#   sudo bash watch.sh --remove   # remove the watch only; the lock stays
#   sudo bash watch.sh --test     # send one Telegram message
#
# VPN off and mode closed is healthy: the lock is doing its job. A message is
# sent only when the daemon is down, pf is off, the rule or the table does not
# match, or a packet past the tunnel is not dropped. A failure is checked until
# the daemon has had time to repair it, so a brief gap does not send a message.
#
# Telegram: lib/telegram.conf.template is copied to
#   /opt/network-kill-switch/telegram.conf (--install keeps a filled-in copy).
# Read only when root owns that file and nobody else can read or write it.

set -uo pipefail
export LC_ALL=C

SRC="$(cd "$(dirname "$0")" && pwd)"

CVL_LABEL=local.network-kill-switch
CVL_DEST_DIR=/opt/network-kill-switch
CVL_DAEMON="${CVL_DEST_DIR}/network-kill-switch-daemon.sh"
CVL_WATCH_LABEL=local.network-kill-switch-watch
CVL_WATCH="${CVL_DEST_DIR}/network-kill-switch-watch.sh"
CVL_WATCH_PLIST=/Library/LaunchDaemons/local.network-kill-switch-watch.plist
CVL_TG_CONF="${CVL_DEST_DIR}/telegram.conf"
CVL_WATCH_LOG=/var/log/network-kill-switch-watch.log

if [ -f "${SRC}/lib/common.sh" ]; then
  # shellcheck source=lib/common.sh
  . "${SRC}/lib/common.sh"
fi

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

need_root() { [ "$(id -u)" = 0 ] || die "must run as root: sudo bash $0 $*"; }

WATCH_LOCK=""
TG_CFG=""
TG_MSG=""
PROBLEMS=""
MODE_NOW=""
PIN_NOW=""
CANARY_NOTE="skipped"
RESEND_SECONDS=600
TG_WHY=""

on_exit() {
  [ -n "${WATCH_LOCK}" ] && rm -rf "${WATCH_LOCK}"
  [ -n "${TG_CFG}" ] && rm -f "${TG_CFG}"
  [ -n "${TG_MSG}" ] && rm -f "${TG_MSG}"
}
trap on_exit EXIT

host_name() {
  local n
  n=$(scutil --get ComputerName 2>/dev/null || hostname 2>/dev/null || printf 'this-mac')
  printf '%s' "${n}" | tr '\n' ' ' | sed 's/[[:space:]]*$//'
}

# Always the installed daemon. A newer checkout must not judge the lock that is
# actually running, or a table comparison after git pull becomes a false alert.
load_daemon() {
  [ -f "${CVL_DAEMON}" ] || die "the lock is not installed (${CVL_DAEMON} is missing)"
  # shellcheck disable=SC1090
  CVL_LIB=1 CVL_NO_NOTIFY=1 . "${CVL_DAEMON}"
}

# How long the daemon may need to put a flushed rule back: one tick, plus an
# exit-country check that can already be running, plus a few seconds. Capped so
# a wild config value cannot hold the hourly job open.
confirm_for() {
  local tick wait max
  tick=${TICK:-5}
  wait=${COUNTRY_WAIT_MAX:-8}
  case "${tick}" in ''|*[!0-9]*) tick=5 ;; esac
  case "${wait}" in ''|*[!0-9]*) wait=8 ;; esac
  max=$((tick + wait + 5))
  [ "${max}" -lt 15 ] && max=15
  [ "${max}" -gt 30 ] && max=30
  printf '%s' "${max}"
}

lock_is_ours() {
  local dir="$1" old cmd age
  old=$(cat "${dir}/pid" 2>/dev/null || true)
  [ -n "${old}" ] && kill -0 "${old}" 2>/dev/null || return 1
  cmd=$(ps -p "${old}" -o command= 2>/dev/null || true)
  case "${cmd}" in
    *network-kill-switch-watch*|*watch.sh*) ;;
    *) return 1 ;;
  esac
  age=$(( $(date +%s) - $(stat -f %m "${dir}" 2>/dev/null || printf 0) ))
  [ "${age}" -lt 300 ]
}

acquire_lock() {
  local dir
  [ -d "${CVL_DEST_DIR}/state" ] || die "the lock is not installed (${CVL_DEST_DIR}/state is missing)"
  dir="${CVL_DEST_DIR}/state/watch.lock"
  if mkdir "${dir}" 2>/dev/null; then
    printf '%s\n' $$ >"${dir}/pid"
    WATCH_LOCK="${dir}"
    return 0
  fi
  # A reused pid after SIGKILL or a power loss must not silence every later check.
  if lock_is_ours "${dir}"; then
    return 1
  fi
  rm -rf "${dir}"
  mkdir "${dir}" 2>/dev/null || return 1
  printf '%s\n' $$ >"${dir}/pid"
  WATCH_LOCK="${dir}"
  return 0
}

add() { PROBLEMS="${PROBLEMS}- $*
"; }

# Drop a surrounding quote pair, and anything a trailing comment left after it.
unquote() {
  local v="$1"
  v=${v%$'\r'}
  v=${v#"${v%%[![:space:]]*}"}
  v=${v%"${v##*[![:space:]]}"}
  case "${v}" in
    \"*) v=${v#\"}; v=${v%%\"*} ;;
    \'*) v=${v#\'}; v=${v%%\'*} ;;
  esac
  v=${v#"${v%%[![:space:]]*}"}
  v=${v%"${v##*[![:space:]]}"}
  printf '%s' "${v}"
}

# Two assignments, not sourced. A token must not be executable as root.
# On failure TG_WHY says which check failed, without the token.
telegram_ready() {
  local perm line key val id="" secret="" rest=""
  TELEGRAM_BOT_TOKEN=""
  TELEGRAM_CHAT_ID=""
  TG_WHY=""
  if [ ! -f "${CVL_TG_CONF}" ]; then
    TG_WHY="telegram is not configured (${CVL_TG_CONF} is missing)"
    return 1
  fi
  if ! path_trusted "${CVL_TG_CONF}"; then
    TG_WHY="telegram.conf is ignored: it or a folder above it is not root-only, or it is a symlink"
    return 1
  fi
  perm=$(stat -f %Lp "${CVL_TG_CONF}" 2>/dev/null) || {
    TG_WHY="telegram.conf could not be read"
    return 1
  }
  # 044: group or other read. The bot token stays root-only.
  if [ $(( 8#${perm} & 044 )) != 0 ]; then
    TG_WHY="telegram.conf is readable by someone other than root (mode ${perm}); message not sent"
    return 1
  fi
  while IFS= read -r line || [ -n "${line}" ]; do
    line=${line%$'\r'}
    case "${line}" in
      ''|\#*) continue ;;
      TELEGRAM_BOT_TOKEN=*|TELEGRAM_CHAT_ID=*) ;;
      *) continue ;;
    esac
    key=${line%%=*}
    val=$(unquote "${line#*=}")
    case "${key}" in
      TELEGRAM_BOT_TOKEN) TELEGRAM_BOT_TOKEN=${val} ;;
      TELEGRAM_CHAT_ID) TELEGRAM_CHAT_ID=${val} ;;
    esac
  done <"${CVL_TG_CONF}"
  id=${TELEGRAM_BOT_TOKEN%%:*}
  secret=${TELEGRAM_BOT_TOKEN#*:}
  if [ -z "${id}" ] || [ "${id}" = "${TELEGRAM_BOT_TOKEN}" ] || [ -z "${secret}" ]; then
    TG_WHY="telegram.conf has no usable bot token or chat id"
    return 1
  fi
  case "${id}" in *[!0-9]*) TG_WHY="telegram.conf has no usable bot token or chat id"; return 1 ;; esac
  case "${secret}" in *[!A-Za-z0-9_-]*) TG_WHY="telegram.conf has no usable bot token or chat id"; return 1 ;; esac
  case "${TELEGRAM_CHAT_ID}" in
    -*) rest=${TELEGRAM_CHAT_ID#-} ;;
    *) rest=${TELEGRAM_CHAT_ID} ;;
  esac
  if [ -z "${rest}" ]; then
    TG_WHY="telegram.conf has no usable bot token or chat id"
    return 1
  fi
  case "${rest}" in *[!0-9]*) TG_WHY="telegram.conf has no usable bot token or chat id"; return 1 ;; esac
  return 0
}

send_telegram() {
  local body
  if ! telegram_ready; then
    say "${TG_WHY}"
    return 2
  fi
  TG_MSG=$(mktemp "${TMPDIR:-/tmp}/nks-tg-text.XXXXXX") || return 1
  chmod 600 "${TG_MSG}" || return 1
  printf '%s\n' "$1" >"${TG_MSG}"
  # -q is first so a user's ~/.curlrc is not applied when this runs under sudo.
  # The URL is on stdin, not in argv and not in a file under TMPDIR.
  body=$(printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' "${TELEGRAM_BOT_TOKEN}" \
    | /usr/bin/curl -q -sS -m 20 --config - -X POST \
        --data-urlencode "chat_id=${TELEGRAM_CHAT_ID}" \
        --data-urlencode "text@${TG_MSG}" 2>&1) || true
  rm -f "${TG_MSG}"
  TG_MSG=""
  body=$(printf '%s\n' "${body}" | sed -E 's#bot[0-9]+:[A-Za-z0-9_-]+#bot[redacted]#g')
  case "${body}" in
    *'"ok":true'*) return 0 ;;
  esac
  say "telegram send failed: $(printf '%s' "${body}" | tr '\n' ' ' | cut -c1-300)"
  return 1
}

# The packet-counter tail changes on every run, so it is not part of "the same alert".
alert_key() {
  printf '%s\n' "${PROBLEMS}" \
    | awk 'index($0, "a packet sent past the tunnel") == 0' \
    | shasum -a 256 \
    | awk 'NR == 1 { print substr($1, 1, 16); exit }'
}

recent_alert() {
  local line t key now
  line=$(cat "${STATE_DIR}/watch-sent" 2>/dev/null || true)
  [ -n "${line}" ] || return 1
  t=${line%% *}
  key=${line#* }
  [ "${t}" = "${line}" ] && key=""
  case "${t}" in ''|*[!0-9]*) return 1 ;; esac
  [ "${key}" = "$(alert_key)" ] || return 1
  now=$(date +%s)
  # A clock step backwards must not suppress alerts forever.
  [ "${now}" -ge "${t}" ] || return 1
  [ $((now - t)) -lt "${RESEND_SECONDS}" ]
}

check_once() {
  local rule verify_out verify_rc
  PROBLEMS=""
  MODE_NOW=$(cat "${MODE_FILE}" 2>/dev/null || true)
  PIN_NOW=$(cat "${PIN_FILE}" 2>/dev/null || true)
  CANARY_NOTE=skipped
  # grep without -q reads the whole launchctl report. With pipefail, grep -q can
  # exit before launchctl finishes and turn a running daemon into a false failure.
  if ! launchctl print "system/${CVL_LABEL}" 2>/dev/null | grep -F 'state = running' >/dev/null; then
    add "daemon is not running"
  fi
  [ -z "${CONFIG_IGNORED:-}" ] || add "settings file is ignored because it is not root-only"
  pf_enabled || add "pf is disabled"
  main_has_apple_anchor \
    || add "main pf ruleset has no com.apple/* anchor, so the rule is not evaluated"
  case "${MODE_NOW}" in
    open|closed|country) ;;
    *) add "mode is '${MODE_NOW:-missing}' (expected open, closed, or country)" ;;
  esac
  MODE=${MODE_NOW}
  PINNED_IF=${PIN_NOW%% *}
  case "${MODE_NOW}" in
    open|closed|country)
      if ! rule_matches_mode; then
        rule=$(anchor_rule)
        add "rule does not match mode ${MODE_NOW}: ${rule:-none}"
      fi
      ;;
  esac
  table_matches || add "table nks_nets does not match the networks the lock should block"
  verify_out=$(cmd_verify 2>&1)
  verify_rc=$?
  case "${verify_rc}" in
    0) CANARY_NOTE=dropped ;;
    2) CANARY_NOTE=not-measured ;;
    *)
      CANARY_NOTE=not-dropped
      add "a packet sent past the tunnel was not dropped: $(printf '%s' "${verify_out}" | tr '\n' '; ' | cut -c1-240)"
      ;;
  esac
}

cmd_check() {
  local now host prev text deadline
  need_root
  load_daemon
  acquire_lock || { say "another check is running"; exit 0; }
  check_once
  if [ -n "${PROBLEMS}" ]; then
    deadline=$(( $(date +%s) + $(confirm_for) ))
    while [ -n "${PROBLEMS}" ] && [ "$(date +%s)" -lt "${deadline}" ]; do
      sleep 2
      check_once
    done
  fi
  now=$(date '+%Y-%m-%dT%H:%M:%S%z')
  host=$(host_name)
  prev=$(cat "${STATE_DIR}/watch-result" 2>/dev/null || true)
  if [ -n "${PROBLEMS}" ]; then
    text="network-kill-switch is NOT enforcing
host: ${host}
when: ${now}
mode: ${MODE_NOW:-unknown}
route: $(route_iface)
${PROBLEMS}"
    say "${now} NOT enforcing"
    printf '%s' "${PROBLEMS}"
    if recent_alert; then
      say "the same alert was sent in the last 10 minutes; not sent again"
    else
      send_telegram "${text}"
      case $? in
        0) printf '%s %s\n' "$(date +%s)" "$(alert_key)" >"${STATE_DIR}/watch-sent" ;;
        2) ;;
        *) say "alert was not delivered; the next check will try again" ;;
      esac
    fi
    printf '%s\n' bad >"${STATE_DIR}/watch-result"
    exit 1
  fi
  say "${now} OK mode=${MODE_NOW:-unknown} canary=${CANARY_NOTE}"
  if [ "${prev}" = bad ]; then
    text="network-kill-switch is enforcing again
host: ${host}
when: ${now}
mode: ${MODE_NOW:-unknown}
tunnel: ${PIN_NOW:-none}
canary: ${CANARY_NOTE}"
    send_telegram "${text}"
    case $? in
      0|2) rm -f "${STATE_DIR}/watch-sent" ;;
      *) say "recovery message was not delivered"; exit 1 ;;
    esac
  fi
  printf '%s\n' ok >"${STATE_DIR}/watch-result"
  exit 0
}

cmd_test() {
  local text
  need_root
  load_daemon
  acquire_lock || die "another check is running"
  telegram_ready || die "${TG_WHY}. Edit ${CVL_TG_CONF}, then retry"
  text="network-kill-switch watch: test message
host: $(host_name)
when: $(date '+%Y-%m-%dT%H:%M:%S%z')
The hourly check can reach this chat."
  send_telegram "${text}" || die "the test message was not delivered"
  say "test message sent"
}

# True when the installed file is missing or both values are still empty, so a
# filled-in token is never replaced by the template.
telegram_conf_blank() {
  local line key val token="" chat=""
  [ -f "${CVL_TG_CONF}" ] || return 0
  [ -r "${CVL_TG_CONF}" ] || return 1
  while IFS= read -r line || [ -n "${line}" ]; do
    line=${line%$'\r'}
    case "${line}" in
      ''|\#*) continue ;;
      TELEGRAM_BOT_TOKEN=*|TELEGRAM_CHAT_ID=*) ;;
      *) continue ;;
    esac
    key=${line%%=*}
    val=$(unquote "${line#*=}")
    case "${key}" in
      TELEGRAM_BOT_TOKEN) token=${val} ;;
      TELEGRAM_CHAT_ID) chat=${val} ;;
    esac
  done <"${CVL_TG_CONF}"
  [ -z "${token}" ] && [ -z "${chat}" ]
}

write_telegram_template() {
  local src="${SRC}/lib/telegram.conf.template"
  [ -f "${src}" ] || die "missing ${src}; run --install from the git checkout"
  if [ -f "${CVL_TG_CONF}" ] && ! telegram_conf_blank; then
    say "  kept ${CVL_TG_CONF}"
    return 0
  fi
  install -o root -g wheel -m 600 "${src}" "${CVL_TG_CONF}"
  say "  ${CVL_TG_CONF} (from ${src})"
}

cmd_install() {
  local plist_src mark nowsz i
  need_root --install
  [ -x "${CVL_DAEMON}" ] || die "the lock is not installed. Run: sudo bash ${SRC}/install.sh"
  plist_src="${SRC}/lib/network-kill-switch-watch.plist"
  [ -f "${plist_src}" ] || die "missing ${plist_src}; run --install from the git checkout"
  bash -n "$0" || die "watch script failed the syntax check"
  plutil -lint "${plist_src}" >/dev/null || die "watch plist is invalid"
  # Stop a check that is still in its repair wait before the script is replaced.
  pause_watch || say "  WARNING: previous watch process is still alive"
  install -o root -g wheel -m 755 "$0" "${CVL_WATCH}"
  install -o root -g wheel -m 644 "${plist_src}" "${CVL_WATCH_PLIST}"
  write_telegram_template
  resume_watch || die "launchd did not accept the watch"
  say "  installed ${CVL_WATCH}"
  say "  ${CVL_WATCH_PLIST} (at boot and every hour)"
  mark=$(stat -f %z "${CVL_WATCH_LOG}" 2>/dev/null || printf 0)
  nowsz=${mark}
  i=0
  # The first check can spend the whole repair window (up to 30 s) re-checking.
  while [ "${i}" -lt 50 ]; do
    i=$((i + 1))
    sleep 1
    nowsz=$(stat -f %z "${CVL_WATCH_LOG}" 2>/dev/null || printf 0)
    [ "${nowsz}" -gt "${mark}" ] && break
  done
  if [ "${nowsz}" -gt "${mark}" ]; then
    say "  first check:"
    tail -c +"$((mark + 1))" "${CVL_WATCH_LOG}" | sed 's/^/    /'
  else
    say "  loaded, but it has not logged a result yet (${CVL_WATCH_LOG})"
  fi
  load_daemon
  if ! telegram_ready; then
    say "  ${TG_WHY}"
    say "  Edit ${CVL_TG_CONF}, then: sudo bash $0 --test"
  fi
}

cmd_remove() {
  need_root --remove
  pause_watch || say "WARNING: watch process is still alive"
  rm -f "${CVL_WATCH_PLIST}" "${CVL_WATCH}"
  say "watch removed. The lock is still installed. ${CVL_TG_CONF} was kept."
}

# bootout returns before the process exits. Wait, or the next bootstrap fails
# and a check still running can page during a reinstall.
pause_watch() {
  local pid i
  launchctl print "system/${CVL_WATCH_LABEL}" >/dev/null 2>&1 || return 0
  pid=$(launchctl print "system/${CVL_WATCH_LABEL}" 2>/dev/null | awk '$1 == "pid" && $2 == "=" { print $3; exit }')
  launchctl bootout "system/${CVL_WATCH_LABEL}" >/dev/null 2>&1 || true
  [ -n "${pid}" ] || return 0
  i=0
  while [ "${i}" -lt 40 ]; do
    kill -0 "${pid}" 2>/dev/null || return 0
    i=$((i + 1))
    sleep 0.5
  done
  return 1
}

resume_watch() {
  local i err
  [ -f "${CVL_WATCH_PLIST}" ] || return 0
  launchctl enable "system/${CVL_WATCH_LABEL}" >/dev/null 2>&1 || true
  err=""
  i=0
  while [ "${i}" -lt 20 ]; do
    if launchctl print "system/${CVL_WATCH_LABEL}" >/dev/null 2>&1; then
      launchctl bootout "system/${CVL_WATCH_LABEL}" >/dev/null 2>&1 || true
    else
      err=$(launchctl bootstrap system "${CVL_WATCH_PLIST}" 2>&1) && return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  [ -n "${err}" ] && say "launchd: ${err}"
  return 1
}

case "${1:-check}" in
  -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
  --install) cmd_install ;;
  --remove) cmd_remove ;;
  --pause) need_root --pause; pause_watch; exit $? ;;
  --resume) need_root --resume; resume_watch; exit $? ;;
  --test) cmd_test ;;
  check) cmd_check ;;
  *) die "unknown argument: $1" ;;
esac
