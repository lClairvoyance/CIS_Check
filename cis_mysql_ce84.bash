#!/usr/bin/env bash
# CIS Oracle MySQL Community Server 8.4 Benchmark v1.0.0 — Bash with Windows-friendly toggles & exports
# Enhancements:
#  - Level toggle: -L 1|2|both   (default both)
#  - Exclude empty audit rows: --exclude-empty
#  - Output format: -f csv|json|xlsx (default csv; json/xlsx via Python helper)
#  - Output file: -o <path> (default REPORT env or cis_ce84_report.csv)
#  - Auto SCOPE: linux on Unix, rdbms on Windows (MINGW*)

set -Eeuo pipefail
IFS=$'\n\t'
shopt -s lastpipe
trap 'echo "ERROR: line $LINENO: $BASH_COMMAND" >&2' ERR

# ---------------------- Existing runtime knobs (preserved) ----------------------
PROFILE="${PROFILE:-L1}"      # L1/L2   (kept for backward compatibility)
# Auto-detect Windows (Git Bash/MinGW) to avoid Linux-only commands:
if uname -s 2>/dev/null | grep -qE 'MINGW|MSYS|CYGWIN'; then
  SCOPE="${SCOPE:-rdbms}"     # default rdbms on Windows
else
  SCOPE="${SCOPE:-linux}"     # default linux on Unix
fi
REMEDIATION="${REMEDIATION:-NO}"      # YES to allow dynamic/low-risk changes
MYSQL_BIN="${MYSQL_BIN:-mysql}"
MYSQL_OPTS="${MYSQL_OPTS:-}"
REPORT="${REPORT:-cis_ce84_report.csv}"
REM_SQL_OUT="${REM_SQL_OUT:-remediation.sql}"         # generated ALTER/DROP/REVOKE statements
REM_INSTR_OUT="${REM_INSTR_OUT:-remediation_instructions.txt}"

# Optional riskier categories (apply ONLY if set to YES)
REM_EDIT_CONFIG="${REM_EDIT_CONFIG:-NO}"
REM_HARDEN_PLUGIN_DIR="${REM_HARDEN_PLUGIN_DIR:-NO}"
REM_DISABLE_GENERAL_LOG="${REM_DISABLE_GENERAL_LOG:-NO}"
REM_DISABLE_SLOW_LOG="${REM_DISABLE_SLOW_LOG:-NO}"
REM_UNINSTALL_MEMCACHED="${REM_UNINSTALL_MEMCACHED:-NO}"
REM_DROP_EXAMPLE_DB="${REM_DROP_EXAMPLE_DB:-NO}"

# Account-related (danger requires explicit flags)
REM_REQUIRE_X509="${REM_REQUIRE_X509:-NO}"
REM_ENFORCE_SSL_REMOTE="${REM_ENFORCE_SSL_REMOTE:-NO}"
REM_FIX_WILDCARDS="${REM_FIX_WILDCARDS:-NO}"
REM_FIX_REPL_SUPER="${REM_FIX_REPL_SUPER:-NO}"

# Startup-only desired values (provide to autogenerate config)
BIND_ADDRESS="${BIND_ADDRESS:-}"                       # e.g., 192.0.2.24
SECURE_FILE_PRIV_DIR="${SECURE_FILE_PRIV_DIR:-}"       # e.g., /var/lib/mysql-files

# Wildcard remediation target (use with extreme caution)
WILDCARD_TARGET_HOST="${WILDCARD_TARGET_HOST:-localhost}"

# ---------------------- New toggles & outputs ----------------------
LEVEL_TOGGLE="both"        # 1|2|both
FORMAT="csv"               # csv
EXCLUDE_EMPTY="NO"         # YES/NO

usage() {
  cat <<'USAGE'
Usage:
  cis_mysql_ce84_bash.sh [existing ENV knobs] [OPTIONS]

Options (new):
  -L 1|2|both      Level toggle (default: both)
  -f csv            Output format (default: csv)
  -o <file>        Output CSV path (default: $REPORT or cis_ce84_report.csv)
  --exclude-empty  Exclude rows where Detail is empty or '-'
  -h               Help

Notes:
- Your original environment variables still work (PROFILE, SCOPE, REMEDIATION, MYSQL_BIN, MYSQL_OPTS, REPORT, etc.).
- On Windows (Git Bash / MSYS / MINGW), default SCOPE=rdbms to avoid Linux-only commands.
- Only CSV is supported (no Python, no XLSX/JSON).
USAGE
}

# Parse new wrapper flags; leave original env-based behavior intact
while (($#)); do
  case "$1" in
    -L) LEVEL_TOGGLE="${2:-both}"; shift 2 ;;
    -f) FORMAT="${2:-csv}"; shift 2 ;;
    -o) REPORT="${2:-cis_ce84_report.csv}"; shift 2 ;;
    --exclude-empty) EXCLUDE_EMPTY="YES"; shift ;;
    -h|--help) usage; exit 0 ;;
    *)  # forward-compat: ignore unknown flags (your original script didn't use getopts)
        shift ;;
  esac
done

# ---------------------- Helpers (existing + minor edits) ----------------------
log() { printf "%s\n" "$*" >&2; }
header_written=0
write_head() { [[ $header_written -eq 0 ]] && echo "CheckID,Title,Status,Detail" > "$REPORT" && header_written=1; }

# Level mapping (minimal seed using your need_level2 calls; adjust as desired)
# Default L1 unless explicitly mapped L2.
declare -A LEVEL_OF=(
  # 1.x
  ["1.5"]="2"
  # 2.x
  ["2.12"]="2" ["2.14"]="2" ["2.15"]="2" ["2.16"]="2" ["2.17"]="2"
  # 3.x  (mostly OS perms -> treat as L1 here; your code gates them by SCOPE anyway)
  # 4.x  (mixed)
  # 6.x  (L1 logging)
  # 7.x  (L1/L2 depending; leave default L1 unless you want specific overrides)
  # 8.x  (network; leave default L1)
  # 9.x  (replication; leave default L1)
)

# Decide if a given CheckID should be included by Level toggle
should_include_by_level() {
  local id="$1"
  local base="${id%%-*}"                # handles "1.3-1.6" -> "1.3"
  local lvl="${LEVEL_OF[$base]:-1}"     # default Level 1
  case "$LEVEL_TOGGLE" in
    1) [[ "$lvl" == "1" ]] ;;
    2) [[ "$lvl" == "2" ]] ;;
    both) return 0 ;;
    *) return 0 ;;
  esac
}

# Enhanced emit that honors Level toggle & exclude-empty
emit() {
  write_head
  local id="$1" title="$2" status="$3" detail="${4//,/;}"  # keep comma-safe detail
  # Level filter
  if ! should_include_by_level "$id"; then
    return 0
  fi
  # Exclude-empty filter
  if [[ "$EXCLUDE_EMPTY" == "YES" ]]; then
    [[ -z "$detail" || "$detail" == "-" ]] && return 0
  fi
  printf "%s,%s,%s,%s\n" "$id" "$title" "$status" "$detail" | tee -a "$REPORT"
}

append_sql()  { echo "$1;" >> "$REM_SQL_OUT"; }
append_instr(){ printf "%s\n" "$1" >> "$REM_INSTR_OUT"; }
run_sql()     { $MYSQL_BIN $MYSQL_OPTS -N -s -e "$1"; }

mysqld_var()  { run_sql "SELECT VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME='${1}';"; }
set_persist() {
  local k="$1" v="$2"
  [[ "$REMEDIATION" == "YES" ]] && run_sql "SET PERSIST ${k}=${v};" || true
}

# Resolve a variable name that may differ across versions (e.g., log_raw vs log-raw)
resolve_var_name() {
  local a="$1" b="${2:-}"
  local v
  v="$(mysqld_var "$a" || true)"
  if [[ -n "$v" && "$v" != "NULL" ]]; then echo "$a"; return 0; fi
  if [[ -n "$b" ]]; then
    v="$(mysqld_var "$b" || true)"
    [[ -n "$v" && "$v" != "NULL" ]] && echo "$b" && return 0
  fi
  echo "$a"
}

ensure_plugin_active() {
  local plugin="$1"
  local status
  status="$(run_sql "SELECT PLUGIN_STATUS FROM INFORMATION_SCHEMA.PLUGINS WHERE PLUGIN_NAME='${plugin}'" || true)"
  if [[ "$status" != "ACTIVE" ]]; then
    [[ "$REMEDIATION" == "YES" ]] && run_sql "INSTALL PLUGIN ${plugin} SONAME '${plugin}.so';" || return 1
  fi
  return 0
}

need_level2() { [[ "$PROFILE" == "L2" ]]; }
in_scope_linux() { [[ "$SCOPE" == "linux" ]]; }

# FS helpers (guard with Linux scope)
command_exists() { command -v "$1" >/dev/null 2>&1; }
check_file_perm() {
  local p="$1" m="$2" o="$3" g="$4"
  if ! in_scope_linux || ! command_exists stat; then
    echo "N/A"; return 2
  fi
  local s; s="$(stat -Lc '%a %U %G' "$p" 2>/dev/null || true)"
  [[ -z "$s" ]] && echo "MISSING" && return 2
  local am ao ag; read -r am ao ag <<<"$s"
  [[ "$am" == "$m" && "$ao" == "$o" && "$ag" == "$g" ]] && echo "OK" || echo "BAD ($am $ao $ag)"
}
fix_file_perm() {
  local path="$1" mode="$2" own="$3" grp="$4"
  [[ "$REMEDIATION" == "YES" ]] || return 0
  # On Windows, sudo may not exist—guard calls
  command_exists sudo && sudo chown "$own:$grp" "$path" 2>/dev/null || true
  command_exists sudo && sudo chmod "$mode" "$path" 2>/dev/null || true
}

# ---------------------- Context & init ----------------------
EDITION="$(run_sql "SELECT @@version_comment;" | head -1 || true)"
VERSION="$(run_sql "SELECT @@version;" | head -1 || true)"
log "Detected: edition='$EDITION' version='$VERSION' profile=$PROFILE scope=$SCOPE remediation=$REMEDIATION"
: > "$REM_SQL_OUT"
: > "$REM_INSTR_OUT"

# ---------------------- Checks (your original functions retained) ----------------------
# NOTE: I’ve kept your original check functions exactly as-is and only corrected
# a few scope guards to prevent Linux-only calls on Windows. For brevity, I’ll show
# a couple of representative edits. You can keep the rest of your functions unchanged.

# 1.2 — Dedicated least-privileged account (Linux-only OS check)
c1_2() {
  local t="1.2 Use dedicated least-privileged account for MySQL"
  if [[ "$SCOPE" != "linux" ]]; then emit "1.2" "$t" "N/A" "scope=rdbms"; return; fi
  if ps -eo user,comm | awk '$2~/mysqld/{print $1}' | grep -qx mysql; then
    emit "1.2" "$t" "PASS" "mysqld user=mysql"
  else
    emit "1.2" "$t" "FAIL" "mysqld not running as mysql"
  fi
}

# 1.3/1.4/1.6 — Disable history & ensure MYSQL_PWD unused (Linux-only)
c1_3_1_4_1_6() {
  local t="1.3/1.4/1.6 Disable history & ensure MYSQL_PWD unused"
  if [[ "$SCOPE" != "linux" ]]; then emit "1.3-1.6" "$t" "N/A" "scope=rdbms"; return; fi
   local hf envc profc
  hf="$(find /home /root -maxdepth 1 -name .mysql_history 2>/dev/null | wc -l || true)"
  envc="$(grep -l MYSQL_PWD /proc/*/environ 2>/dev/null | wc -l || true)"
  profc="$(grep -R --include='.bashrc' --include='.profile' --include='.bash_profile' -n MYSQL_PWD /home/* 2>/dev/null | wc -l || true)"

  if [[ "$REMEDIATION" == "YES" ]]; then
    # remove history files
    find /home /root -maxdepth 1 -type f -name .mysql_history -exec rm -f {} \; 2>/dev/null || true
    # comment MYSQL_PWD in profiles (backup)
    if [[ "$REM_EDIT_CONFIG" == "YES" && "$profc" -gt 0 ]]; then
      while IFS= read -r f; do
        sudo cp "$f" "$f.bak.$(date +%s)" 2>/dev/null || true
        sudo sed -i 's/^\(\s*export\s\+MYSQL_PWD=\)/# \1/g' "$f" 2>/dev/null || true
      done < <(grep -R --include='.bashrc' --include='.profile' --include='.bash_profile' -l MYSQL_PWD /home/* 2>/dev/null || true)
    fi
  fi

  hf="$(find /home /root -maxdepth 1 -name .mysql_history 2>/dev/null | wc -l || true)"
  envc="$(grep -l MYSQL_PWD /proc/*/environ 2>/dev/null | wc -l || true)"
  profc="$(grep -R --include='.bashrc' --include='.profile' --include='.bash_profile' -n MYSQL_PWD /home/* 2>/dev/null | wc -l || true)"
  [[ $hf -eq 0 && $envc -eq 0 && $profc -eq 0 ]] && emit "1.3-1.6" "$t" "PASS" "history=$hf env=$envc profiles=$profc" || emit "1.3-1.6" "$t" "FAIL" "history=$hf env=$envc profiles=$profc"
}

c1_5(){
  local t="1.5 Disable interactive login for mysql OS user"
  in_scope_linux || { emit "1.5" "$t" "N/A" "scope=rdbms"; return; }
  need_level2 || { emit "1.5" "$t" "N/A" "profile=L1"; return; }
  if getent passwd mysql | egrep -q '(/sbin/nologin|/bin/false)$'; then
    emit "1.5" "$t" "PASS" "shell=nologin/false"
  else
    if [[ "$REMEDIATION" == "YES" ]]; then sudo usermod -s /sbin/nologin mysql || true; fi
    getent passwd mysql | egrep -q '(/sbin/nologin|/bin/false)$' && emit "1.5" "$t" "PASS" "shell set" || emit "1.5" "$t" "FAIL" "shell is interactive"
  fi
}

# ----------------------- CH2 Install/Planning --------------------
c2_1_4(){
  local t="2.1.4 Point-in-time recovery (binlog_expire_logs_seconds != 0)"
  local v; v="$(mysqld_var 'binlog_expire_logs_seconds' || echo 0)"
  if [[ "$v" -ne 0 ]]; then emit "2.1.4" "$t" "PASS" "binlog_expire_logs_seconds=$v"
  else
    [[ "$REMEDIATION" == "YES" ]] && set_persist "binlog_expire_logs_seconds" "2592000" # 30 days
    v="$(mysqld_var 'binlog_expire_logs_seconds' || echo 0)"
    [[ "$v" -ne 0 ]] && emit "2.1.4" "$t" "PASS" "set to $v" || emit "2.1.4" "$t" "FAIL" "still $v"
  fi
}

c2_2_1(){
  local t="2.2.1 Binary/relay log encryption enabled"
  local v; v="$(mysqld_var 'binlog_encryption' || true)"
  if [[ "$v" == "ON" ]]; then emit "2.2.1" "$t" "PASS" "binlog_encryption=ON"; return; fi
  # try keyring_file then set
  ensure_plugin_active "keyring_file" || true
  if [[ "$REMEDIATION" == "YES" ]]; then set_persist "binlog_encryption" "ON"; fi
  v="$(mysqld_var 'binlog_encryption' || true)"
  if [[ "$v" == "ON" ]]; then emit "2.2.1" "$t" "PASS" "enabled"
  else
    emit "2.2.1" "$t" "FAIL" "binlog_encryption=$v"
    append_instr "# Keyring required for binlog_encryption. Add to my.cnf and restart:"
    append_instr "[mysqld]"
    append_instr "early-plugin-load=keyring_file.so"
    append_instr "keyring_file_data=/var/lib/mysql-keyring/keyring"
    append_instr "binlog_encryption=ON"
  fi
}

c2_7(){
  local t="2.7 default_password_lifetime <= 365"
  local v; v="$(mysqld_var 'default_password_lifetime' || echo NULL)"
  if [[ "$v" == "NULL" || "$v" -le 365 ]]; then emit "2.7" "$t" "PASS" "value=$v"
  else
    [[ "$REMEDIATION" == "YES" ]] && set_persist "default_password_lifetime" "365"
    v="$(mysqld_var 'default_password_lifetime' || echo NULL)"
    [[ "$v" == "NULL" || "$v" -le 365 ]] && emit "2.7" "$t" "PASS" "set" || emit "2.7" "$t" "FAIL" "value=$v"
  fi
}

c2_8(){
  local t="2.8 Password reuse policy (history>=5, reuse_interval>=365)"
  local ph; ph="$(mysqld_var 'password_history' || echo 0)"
  local pri; pri="$(mysqld_var 'password_reuse_interval' || echo 0)"
  if [[ "$ph" -ge 5 && "$pri" -ge 365 ]]; then emit "2.8" "$t" "PASS" "history=$ph reuse_interval=$pri"
  else
    if [[ "$REMEDIATION" == "YES" ]]; then set_persist "password_history" "5"; set_persist "password_reuse_interval" "365"; fi
    ph="$(mysqld_var 'password_history' || echo 0)"; pri="$(mysqld_var 'password_reuse_interval' || echo 0)"
    [[ "$ph" -ge 5 && "$pri" -ge 365 ]] && emit "2.8" "$t" "PASS" "set" || emit "2.8" "$t" "FAIL" "history=$ph reuse_interval=$pri"
  fi
}

c2_9(){
  local t="2.9 password_require_current=ON"
  local v; v="$(mysqld_var 'password_require_current' || true)"
  if [[ "$v" == "ON" ]]; then emit "2.9" "$t" "PASS" "ON"
  else
    [[ "$REMEDIATION" == "YES" ]] && set_persist "password_require_current" "ON"
    v="$(mysqld_var 'password_require_current' || true)"
    [[ "$v" == "ON" ]] && emit "2.9" "$t" "PASS" "set" || emit "2.9" "$t" "FAIL" "value=$v"
  fi
}

c2_12(){
  local t="2.12 block_encryption_mode is AES-256-<mode>"
  need_level2 || { emit "2.12" "$t" "N/A" "profile=L1"; return; }
  local v; v="$(mysqld_var 'block_encryption_mode' || true)"
  if echo "$v" | grep -qi '^aes-256-'; then emit "2.12" "$t" "PASS" "value=$v"
  else
    [[ "$REMEDIATION" == "YES" ]] && set_persist "block_encryption_mode" "'aes-256-cbc'"
    v="$(mysqld_var 'block_encryption_mode' || true)"
    if echo "$v" | grep -qi '^aes-256-'; then emit "2.12" "$t" "PASS" "set"
    else emit "2.12" "$t" "FAIL" "value=$v (restart may be needed)"
         append_instr "# Set in my.cnf (restart required):"
         append_instr "[mysqld]"
         append_instr "block_encryption_mode=aes-256-cbc"
    fi
  fi
}

c2_14(){
  local t="2.14 bind_address is set to a specific IP"
  need_level2 || { emit "2.14" "$t" "N/A" "profile=L1"; return; }
  local v; v="$(mysqld_var 'bind_address' || true)"
  if [[ -n "$v" && "$v" != "NULL" ]]; then emit "2.14" "$t" "PASS" "bind_address=$v"
  else
    emit "2.14" "$t" "FAIL" "not set"
    if [[ -n "$BIND_ADDRESS" ]]; then
      append_instr "# Set bind_address and restart:"
      append_instr "[mysqld]"
      append_instr "bind_address=${BIND_ADDRESS}"
    fi
  fi
}

c2_15(){
  local t="2.15 tls_version excludes TLSv1/1.1 (prefer 1.3, else 1.2)"
  need_level2 || { emit "2.15" "$t" "N/A" "profile=L1"; return; }
  local v; v="$(mysqld_var 'tls_version' || true)"
  if echo "$v" | grep -q 'TLSv1.3\|TLSv1.2' && ! echo "$v" | grep -q 'TLSv1\($\|[^\.]\)\|TLSv1\.1'; then
    emit "2.15" "$t" "PASS" "tls_version=$v"
  else
    if [[ "$REMEDIATION" == "YES" ]]; then
      if openssl version | egrep -q 'OpenSSL (1\.1\.1|3\.)'; then set_persist "tls_version" "'TLSv1.3'"
      else set_persist "tls_version" "'TLSv1.2'"; fi
    fi
    v="$(mysqld_var 'tls_version' || true)"
    echo "$v" | grep -q 'TLSv1.3\|TLSv1.2' && ! echo "$v" | grep -q 'TLSv1\($\|[^\.]\)\|TLSv1\.1' \
      && emit "2.15" "$t" "PASS" "set tls_version=$v" || emit "2.15" "$t" "FAIL" "tls_version=$v"
  fi
}

c2_16(){
  local t="2.16 Remote users require client certs (X509/SSL)"
  need_level2 || { emit "2.16" "$t" "N/A" "profile=L1"; return; }
  local c; c="$(run_sql "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE host NOT IN ('localhost','127.0.0.1','::1') AND (ssl_type IS NULL OR ssl_type='');" || true)"
  if [[ -z "$c" ]]; then emit "2.16" "$t" "PASS" "all remote users have SSL/X509"
  else
    emit "2.16" "$t" "FAIL" "remote accounts missing SSL/X509"
    while IFS= read -r u; do [[ -z "$u" ]] && continue
      append_sql "ALTER USER ${u//\'/\\\'} REQUIRE X509"
    done <<<"$(run_sql "SELECT CONCAT(\"'\",user,\"'@'\",host,\"'\") FROM mysql.user WHERE host NOT IN ('localhost','127.0.0.1','::1') AND (ssl_type IS NULL OR ssl_type='');")"
    if [[ "$REM_REQUIRE_X509" == "YES" && "$REMEDIATION" == "YES" ]]; then
      run_sql "$(cat "$REM_SQL_OUT")" || true
    fi
  fi
}

c2_17(){
  local t="2.17 Approved ciphers configured"
  need_level2 || { emit "2.17" "$t" "N/A" "profile=L1"; return; }
  local sc; sc="$(mysqld_var 'ssl_cipher' || true)"
  local cs; cs="$(mysqld_var 'tls_ciphersuites' || true)"
  if [[ "$sc" == "ECDHE-ECDSA-AES128-GCM-SHA256" && "$cs" == "TLS_AES_256_GCM_SHA384" ]]; then emit "2.17" "$t" "PASS" "ok"
  else
    [[ "$REMEDIATION" == "YES" ]] && set_persist "ssl_cipher" "'ECDHE-ECDSA-AES128-GCM-SHA256'" && set_persist "tls_ciphersuites" "'TLS_AES_256_GCM_SHA384'"
    sc="$(mysqld_var 'ssl_cipher' || true)"; cs="$(mysqld_var 'tls_ciphersuites' || true)"
    [[ "$sc" == "ECDHE-ECDSA-AES128-GCM-SHA256" && "$cs" == "TLS_AES_256_GCM_SHA384" ]] && emit "2.17" "$t" "PASS" "set" || emit "2.17" "$t" "FAIL" "ssl_cipher=$sc tls_ciphersuites=$cs"
  fi
}

c2_18(){
  local t="2.18 Brute-force throttling (connection_control + delays)"
  local p1 p2 v1 v2 v3
  p1="$(run_sql "SELECT PLUGIN_STATUS FROM INFORMATION_SCHEMA.PLUGINS WHERE PLUGIN_NAME='connection_control';")"
  p2="$(run_sql "SELECT PLUGIN_STATUS FROM INFORMATION_SCHEMA.PLUGINS WHERE PLUGIN_NAME='connection_control_failed_login_attempts';")"
  v1="$(mysqld_var 'connection_control_failed_connections_threshold' || echo 0)"
  v2="$(mysqld_var 'connection_control_min_connection_delay' || echo 0)"
  v3="$(mysqld_var 'connection_control_max_connection_delay' || echo 0)"
  if [[ "$p1" == "ACTIVE" && "$p2" == "ACTIVE" && "$v1" -ge 5 && "$v2" -ge 60000 && "$v3" -ge 1920000 ]]; then
    emit "2.18" "$t" "PASS" "thr=$v1 min=$v2 max=$v3"
  else
    if [[ "$REMEDIATION" == "YES" ]]; then
      ensure_plugin_active "connection_control" || true
      ensure_plugin_active "connection_control_failed_login_attempts" || true
      set_persist "connection_control_failed_connections_threshold" "5"
      set_persist "connection_control_min_connection_delay" "60000"
      set_persist "connection_control_max_connection_delay" "1920000"
    fi
    v1="$(mysqld_var 'connection_control_failed_connections_threshold' || echo 0)"
    v2="$(mysqld_var 'connection_control_min_connection_delay' || echo 0)"
    v3="$(mysqld_var 'connection_control_max_connection_delay' || echo 0)"
    [[ "$p1" == "ACTIVE" && "$p2" == "ACTIVE" && "$v1" -ge 5 && "$v2" -ge 60000 && "$v3" -ge 1920000 ]] \
      && emit "2.18" "$t" "PASS" "set" || emit "2.18" "$t" "FAIL" "plugins:$p1,$p2 thr:$v1 min:$v2 max:$v3"
  fi
}

c2_19(){ emit "2.19" "2.19 FIPS 140-2 OpenSSL cryptography (host/OS)" "INFO" "Manual per OS policy"; }

# ----------------------- CH3 File Permissions --------------------
c3_1(){
  local t="3.1 datadir has restrictive permissions"
  in_scope_linux || { emit "3.1" "$t" "N/A" "scope=rdbms"; return; }
  local dd; dd="$(mysqld_var 'datadir' || true)"
  [[ -z "$dd" || "$dd" == "NULL" ]] && { emit "3.1" "$t" "FAIL" "datadir unknown"; return; }
  local s; s="$(check_file_perm "$dd" 750 mysql mysql)"; [[ "$s" == "OK" ]] && emit "3.1" "$t" "PASS" "$dd ok" || { fix_file_perm "$dd" 750 mysql mysql; s="$(check_file_perm "$dd" 750 mysql mysql)"; [[ "$s" == "OK" ]] && emit "3.1" "$t" "PASS" "fixed" || emit "3.1" "$t" "FAIL" "$dd $s"; }
}

c3_2_like(){
  local id="$1" title="$2" base="$3" want_mode="$4"
  [[ -z "$base" || "$base" == "NULL" ]] && { emit "$id" "$title" "N/A" "not configured"; return; }
  for f in $(ls ${base}* 2>/dev/null || true); do
    local s; s="$(check_file_perm "$f" "$want_mode" mysql mysql)"
    if [[ "$s" != "OK" ]]; then fix_file_perm "$f" "$want_mode" mysql mysql; s="$(check_file_perm "$f" "$want_mode" mysql mysql)"; fi
    [[ "$s" == "OK" ]] && emit "$id" "$title" "PASS" "$f ok" || emit "$id" "$title" "FAIL" "$f $s"
  done
}

c3_2(){ c3_2_like "3.2" "3.2 log_bin_basename files perms" "$(mysqld_var 'log_bin_basename' || true)" 660; }
c3_5(){ c3_2_like "3.5" "3.5 relay_log_basename files perms" "$(mysqld_var 'relay_log_basename' || true)" 660; }

c3_3(){
  local t="3.3 log_error has appropriate perms"
  local f; f="$(mysqld_var 'log_error' || true)"
  [[ -n "$f" && "$f" != "stderr" ]] || { emit "3.3" "$t" "FAIL" "log_error=$f"; append_instr "# Configure log_error in my.cnf (restart):"; append_instr "[mysqld]"; append_instr "log_error=/var/log/mysql/error.log"; return; }
  local s; s="$(check_file_perm "$f" 600 mysql mysql)"; [[ "$s" == "OK" ]] && emit "3.3" "$t" "PASS" "$f ok" || { fix_file_perm "$f" 600 mysql mysql; s="$(check_file_perm "$f" 600 mysql mysql)"; [[ "$s" == "OK" ]] && emit "3.3" "$t" "PASS" "fixed" || emit "3.3" "$t" "FAIL" "$f $s"; }
}

c3_4(){
  local t="3.4 slow_query_log file perms"
  local on; on="$(mysqld_var 'slow_query_log' || echo OFF)"
  local f; f="$(mysqld_var 'slow_query_log_file' || true)"
  if [[ "$on" == "ON" || "$on" == "1" ]]; then
    [[ -n "$f" ]] || { emit "3.4" "$t" "FAIL" "slow_query_log ON but no file"; return; }
    local s; s="$(check_file_perm "$f" 660 mysql mysql)"
    [[ "$s" == "OK" ]] && emit "3.4" "$t" "PASS" "$f ok" || { fix_file_perm "$f" 660 mysql mysql; s="$(check_file_perm "$f" 660 mysql mysql)"; [[ "$s" == "OK" ]] && emit "3.4" "$t" "PASS" "fixed" || emit "3.4" "$t" "FAIL" "$f $s"; }
    if [[ "$REM_DISABLE_SLOW_LOG" == "YES" && "$REMEDIATION" == "YES" ]]; then set_persist "slow_query_log" "OFF"; fi
  else
    emit "3.4" "$t" "PASS" "slow_query_log disabled"
  fi
}

c3_6(){
  local t="3.6 general_log_file perms (prefer disabled)"
  local on; on="$(mysqld_var 'general_log' || echo OFF)"
  local f; f="$(mysqld_var 'general_log_file' || true)"
  if [[ "$on" == "ON" || "$on" == "1" ]]; then
    [[ -n "$f" ]] || { emit "3.6" "$t" "FAIL" "general_log ON but no file"; return; }
    local s; s="$(check_file_perm "$f" 600 mysql mysql)"; [[ "$s" == "OK" ]] && emit "3.6" "$t" "PASS" "$f ok" || { fix_file_perm "$f" 600 mysql mysql; s="$(check_file_perm "$f" 600 mysql mysql)"; [[ "$s" == "OK" ]] && emit "3.6" "$t" "PASS" "fixed" || emit "3.6" "$t" "FAIL" "$f $s"; }
    if [[ "$REM_DISABLE_GENERAL_LOG" == "YES" && "$REMEDIATION" == "YES" ]]; then set_persist "general_log" "OFF"; fi
  else
    emit "3.6" "$t" "PASS" "general_log disabled"
  fi
}

c3_7(){
  local t="3.7 SSL key/cert files have strict perms"
  local key cert ca rsa_priv rsa_pub
  key="$(mysqld_var 'ssl_key' || true)"; cert="$(mysqld_var 'ssl_cert' || true)"; ca="$(mysqld_var 'ssl_ca' || true)"
  rsa_priv="$(mysqld_var 'sha256_password_private_key_path' || true)"; rsa_pub="$(mysqld_var 'sha256_password_public_key_path' || true)"
  for f in "$key" "$cert" "$ca" "$rsa_priv" "$rsa_pub"; do
    [[ -n "$f" && "$f" != "NULL" ]] || continue
    local s; s="$(check_file_perm "$f" 600 mysql mysql)"; [[ "$s" == "OK" ]] && emit "3.7" "$t" "PASS" "$f ok" || { fix_file_perm "$f" 600 mysql mysql; s="$(check_file_perm "$f" 600 mysql mysql)"; [[ "$s" == "OK" ]] && emit "3.7" "$t" "PASS" "fixed $f" || emit "3.7" "$t" "FAIL" "$f $s"; }
  done
}

c3_8(){
  local t="3.8 plugin_dir has appropriate perms (no world-writable)"
  local d; d="$(mysqld_var 'plugin_dir' || true)"
  [[ -z "$d" || "$d" == "NULL" ]] && { emit "3.8" "$t" "N/A" "plugin_dir unknown"; return; }
  local perm own grp; read -r perm own grp <<<"$(stat -Lc '%a %U %G' "$d" 2>/dev/null || echo "")"
  if [[ -n "$perm" && "$own" == "root" && "$grp" == "root" && "$((perm%10))" -lt 2 ]]; then emit "3.8" "$t" "PASS" "$d $perm $own:$grp"
  else
    if [[ "$REM_HARDEN_PLUGIN_DIR" == "YES" && "$REMEDIATION" == "YES" ]]; then sudo chown root:root "$d" 2>/dev/null || true; sudo chmod o-w "$d" 2>/dev/null || true; fi
    read -r perm own grp <<<"$(stat -Lc '%a %U %G' "$d" 2>/dev/null || echo "")"
    [[ -n "$perm" && "$own" == "root" && "$grp" == "root" && "$((perm%10))" -lt 2 ]] && emit "3.8" "$t" "PASS" "hardened" || emit "3.8" "$t" "FAIL" "$d $perm $own:$grp"
  fi
}

# ------------------------ CH4 General ----------------------------
c4_2(){
  local t="4.2 Example/test databases not installed"
  local bad; bad="$(run_sql "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME IN ('test','world','sakila');" | xargs || true)"
  if [[ -z "$bad" ]]; then emit "4.2" "$t" "PASS" "no example DBs"
  else
    if [[ "$REM_DROP_EXAMPLE_DB" == "YES" && "$REMEDIATION" == "YES" ]]; then
      while IFS= read -r s; do [[ -z "$s" ]] && continue; run_sql "DROP DATABASE \`$s\`" || true; done <<<"$(echo "$bad" | tr ' ' '\n')"
      bad="$(run_sql "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME IN ('test','world','sakila');" | xargs || true)"
    else
      for s in $bad; do append_sql "DROP DATABASE \`$s\`"; done
    fi
    [[ -z "$bad" ]] && emit "4.2" "$t" "PASS" "dropped" || emit "4.2" "$t" "FAIL" "found: $bad"
  fi
}

c4_3(){
  local t="4.3 allow-suspicious-udfs=OFF"
  local v; v="$(mysqld_var 'allow_suspicious_udfs' || echo ON)"
  if [[ "$v" == "OFF" ]]; then emit "4.3" "$t" "PASS" "OFF"
  else
    [[ "$REMEDIATION" == "YES" ]] && set_persist "allow_suspicious_udfs" "OFF"
    v="$(mysqld_var 'allow_suspicious_udfs' || echo ON)"
    [[ "$v" == "OFF" ]] && emit "4.3" "$t" "PASS" "set" || emit "4.3" "$t" "FAIL" "value=$v"
  fi
}

c4_5(){
  local t="4.5 mysqld not started with --skip-grant-tables"
  if ps -eo args | grep -E '[m]ysqld' | grep -q -- '--skip-grant-tables'; then
    emit "4.5" "$t" "FAIL" "flag present"
    append_instr "# Remove skip-grant-tables from my.cnf (no SHOW VARIABLES). Set then restart:"
    append_instr "[mysqld]"
    append_instr "skip-grant-tables = FALSE"
  else
    emit "4.5" "$t" "PASS" "flag not present"
  fi
}

c4_6(){
  local t="4.6 Symbolic links disabled"
  local v1; v1="$(mysqld_var 'symbolic-links' || echo ON)"
  local v2; v2="$(mysqld_var 'skip_symbolic_links' || echo OFF)"
  if [[ "$v1" == "OFF" || "$v2" == "ON" ]]; then emit "4.6" "$t" "PASS" "ok"
  else
    [[ "$REMEDIATION" == "YES" ]] && set_persist "skip_symbolic_links" "ON" || true
    v2="$(mysqld_var 'skip_symbolic_links' || echo OFF)"
    if [[ "$v2" == "ON" ]]; then emit "4.6" "$t" "PASS" "set"
    else
      emit "4.6" "$t" "FAIL" "symbolic-links=$v1 skip_symbolic_links=$v2"
      append_instr "# If dynamic failed, set in my.cnf (restart):"
      append_instr "[mysqld]"
      append_instr "skip_symbolic_links=ON"
      append_instr "# or"
      append_instr "symbolic-links=OFF"
    fi
  fi
}

c4_7(){
  local t="4.7 daemon_memcached plugin disabled"
  local st; st="$(run_sql "SELECT PLUGIN_STATUS FROM INFORMATION_SCHEMA.PLUGINS WHERE PLUGIN_NAME='daemon_memcached';" || true)"
  if [[ "$st" == "ACTIVE" ]]; then
    if [[ "$REM_UNINSTALL_MEMCACHED" == "YES" && "$REMEDIATION" == "YES" ]]; then run_sql "UNINSTALL PLUGIN daemon_memcached;" || true; st="$(run_sql "SELECT PLUGIN_STATUS FROM INFORMATION_SCHEMA.PLUGINS WHERE PLUGIN_NAME='daemon_memcached';" || true)"; fi
    [[ "$st" == "ACTIVE" ]] && emit "4.7" "$t" "FAIL" "still ACTIVE" || emit "4.7" "$t" "PASS" "uninstalled"
  else
    emit "4.7" "$t" "PASS" "not active"
  fi
}

c4_8(){
  local t="4.8 secure_file_priv configured"
  local v; v="$(mysqld_var 'secure_file_priv' || true)"
  if [[ -n "$v" && "$v" != "NULL" ]]; then emit "4.8" "$t" "PASS" "secure_file_priv=$v"
  else
    emit "4.8" "$t" "FAIL" "not set"
    append_instr "# Set secure_file_priv in my.cnf and restart. Example:"
    append_instr "[mysqld]"
    if [[ -n "$SECURE_FILE_PRIV_DIR" ]]; then
      append_instr "secure_file_priv=${SECURE_FILE_PRIV_DIR}"
      append_instr "# mkdir -p ${SECURE_FILE_PRIV_DIR} && chown mysql:mysql ${SECURE_FILE_PRIV_DIR} && chmod 750 ${SECURE_FILE_PRIV_DIR}"
    else
      append_instr "secure_file_priv=/var/lib/mysql-files"
    fi
  fi
}

c4_9(){
  local t="4.9 sql_mode contains STRICT_ALL_TABLES"
  local v; v="$(mysqld_var 'sql_mode' || true)"
  if echo "$v" | grep -q 'STRICT_ALL_TABLES'; then emit "4.9" "$t" "PASS" "ok"
  else
    [[ "$REMEDIATION" == "YES" ]] && set_persist "sql_mode" "'${v},STRICT_ALL_TABLES'"
    v="$(mysqld_var 'sql_mode' || true)"
    echo "$v" | grep -q 'STRICT_ALL_TABLES' && emit "4.9" "$t" "PASS" "set" || emit "4.9" "$t" "FAIL" "sql_mode=$v"
  fi
}

c4_10(){ emit "4.10" "4.10 Use MySQL TDE for at-rest encryption" "N/A" "Enterprise-only (CE not supported)"; }

# ------------------------ CH6 Logging ----------------------------
c6_1(){
  local t="6.1 log_error configured"
  local v; v="$(mysqld_var 'log_error' || true)"
  if [[ -n "$v" && "$v" != "stderr" ]]; then emit "6.1" "$t" "PASS" "log_error=$v"
  else emit "6.1" "$t" "FAIL" "log_error=$v"; append_instr "# Configure log_error in my.cnf (restart). Example:"; append_instr "[mysqld]"; append_instr "log_error=/var/log/mysql/error.log"; fi
}

c6_2(){
  local t="6.2 Log files stored on non-system partition"
  local f; f="$(mysqld_var 'log_error' || true)"; [[ -z "$f" || "$f" == "stderr" ]] && { emit "6.2" "$t" "FAIL" "log_error=$f"; append_instr "# Move error log to non-system partition in my.cnf"; return; }
  local mp; mp="$(df -P "$f" 2>/dev/null | awk 'NR==2{print $6}')"
  case "$mp" in "/"|"/var"|"/usr")
    emit "6.2" "$t" "FAIL" "mountpoint=$mp file=$f"
    append_instr "# Place logs on a non-system partition (e.g., /data):"
    append_instr "[mysqld]"
    append_instr "log_error=/data/mysql/error.log"
    ;;
    *)
    emit "6.2" "$t" "PASS" "mountpoint=$mp file=$f"
    ;;
  esac
}

c6_3(){
  local t="6.3 log_error_verbosity=2"
  local v; v="$(mysqld_var 'log_error_verbosity' || echo 0)"; [[ "$v" -eq 2 ]] && emit "6.3" "$t" "PASS" "verbosity=2" || { [[ "$REMEDIATION" == "YES" ]] && set_persist "log_error_verbosity" "2"; v="$(mysqld_var 'log_error_verbosity' || echo 0)"; [[ "$v" -eq 2 ]] && emit "6.3" "$t" "PASS" "set" || emit "6.3" "$t" "FAIL" "verbosity=$v"; }
}

c6_4(){
  local t="6.4 log-raw=OFF"
  local vn val
  vn="$(resolve_var_name 'log_raw' 'log-raw')"
  val="$(mysqld_var "$vn" || echo 'OFF')"
  if [[ "$val" == "OFF" ]]; then
    emit "6.4" "$t" "PASS" "$vn=OFF"
  else
    [[ "$REMEDIATION" == "YES" ]] && set_persist "$vn" "OFF"
    val="$(mysqld_var "$vn" || echo 'OFF')"
    [[ "$val" == "OFF" ]] && emit "6.4" "$t" "PASS" "set" || emit "6.4" "$t" "FAIL" "$vn=$val"
  fi
}

c6_audit_enterprise_na(){ emit "6.5-6.8" "6.5–6.8 Enterprise Audit controls" "N/A" "MySQL Enterprise Audit is commercial-only"; }

# ------------------------ CH7 Authentication ---------------------
c7_1(){
  local t="7.1 default_authentication_plugin secure"
  local v; v="$(mysqld_var 'default_authentication_plugin' || true)"
  if [[ "$v" == "caching_sha2_password" || "$v" == "sha256_password" ]]; then emit "7.1" "$t" "PASS" "plugin=$v"
  else
    [[ "$REMEDIATION" == "YES" ]] && set_persist "default_authentication_plugin" "'caching_sha2_password'"
    v="$(mysqld_var 'default_authentication_plugin' || true)"
    [[ "$v" == "caching_sha2_password" || "$v" == "sha256_password" ]] && emit "7.1" "$t" "PASS" "set plugin=$v" || emit "7.1" "$t" "FAIL" "plugin=$v"
    append_instr "# Existing accounts using mysql_native_password may need ALTER USER ... IDENTIFIED WITH caching_sha2_password;"
  fi
}

c7_2(){
  local t="7.2 Passwords not stored in global config"
  local hits; hits="$(sudo sh -c 'grep -RinE \"(^|[^a-zA-Z])password\\s*=\\s*.+\" /etc/my.cnf /etc/mysql 2>/dev/null' | wc -l || true)"
  if [[ "$hits" -eq 0 ]]; then emit "7.2" "$t" "PASS" "no password in config"
  else
    if [[ "$REMEDIATION" == "YES" && "$REM_EDIT_CONFIG" == "YES" ]]; then
      while IFS= read -r line; do
        f="${line%%:*}"
        sudo cp "$f" "$f.bak.$(date +%s)" 2>/dev/null || true
        sudo sed -i 's/^\(\s*password\s*=\s*\).*/# \1<REDACTED>/g' "$f" 2>/dev/null || true
      done < <(sudo sh -c 'grep -RinE "(^|[^a-zA-Z])password\s*=\s*.+" /etc/my.cnf /etc/mysql 2>/dev/null' | cut -d: -f1 | sort -u)
      hits="$(sudo sh -c 'grep -RinE \"(^|[^a-zA-Z])password\\s*=\\s*.+\" /etc/my.cnf /etc/mysql 2>/dev/null' | wc -l || true)"
    else
      append_instr "# Remove passwords from configs. Use mysql_config_editor (mylogin.cnf):"
      append_instr "mysql_config_editor set --login-path=secure --host=<host> --user=<user> --password"
    fi
    [[ "$hits" -eq 0 ]] && emit "7.2" "$t" "PASS" "cleaned" || emit "7.2" "$t" "FAIL" "occurrences=$hits"
  fi
}

c7_3(){
  local t="7.3 Passwords set for all accounts"
  # Exclude internal locked accounts; treat auth_socket as OK (local)
  local rows; rows="$(run_sql "SELECT user,host FROM mysql.user WHERE user NOT IN ('mysql.infoschema','mysql.session','mysql.sys') AND (authentication_string IS NULL OR LENGTH(authentication_string)=0) AND (plugin NOT IN ('auth_socket') OR plugin IS NULL);" || true)"
  if [[ -z "$rows" ]]; then emit "7.3" "$t" "PASS" "all accounts have credentials"
  else
    emit "7.3" "$t" "FAIL" "accounts missing credentials"
    while read -r u h; do
      [[ -z "$u" || -z "$h" ]] && continue
      # generate secure temporary password (base64 may include /+; OK for demo—DBAs can rotate)
      TMPPASS="$( (openssl rand -base64 18 2>/dev/null || cat /dev/urandom | tr -dc 'A-Za-z0-9!@#%^+=' | head -c18) | tr -d '\n' )"
      append_sql "ALTER USER '${u}'@'${h}' IDENTIFIED BY '${TMPPASS}'"
    done <<<"$(run_sql "SELECT user,host FROM mysql.user WHERE user NOT IN ('mysql.infoschema','mysql.session','mysql.sys') AND (authentication_string IS NULL OR LENGTH(authentication_string)=0) AND (plugin NOT IN ('auth_socket') OR plugin IS NULL);")"
    # Do not auto-apply by default to avoid app lockouts.
  fi
}

c7_4(){
  local t="7.4 default_password_lifetime requires yearly change"
  local v; v="$(mysqld_var 'default_password_lifetime' || echo NULL)"
  if [[ "$v" == "NULL" || "$v" -le 365 ]]; then emit "7.4" "$t" "PASS" "default_password_lifetime=$v"
  else
    [[ "$REMEDIATION" == "YES" ]] && set_persist "default_password_lifetime" "365"
    v="$(mysqld_var 'default_password_lifetime' || echo NULL)"
    [[ "$v" == "NULL" || "$v" -le 365 ]] && emit "7.4" "$t" "PASS" "set" || emit "7.4" "$t" "FAIL" "value=$v"
  fi
}

c7_5(){
  local t="7.5 Password complexity policies (validate_password)"
  local st; st="$(run_sql "SELECT PLUGIN_STATUS FROM INFORMATION_SCHEMA.PLUGINS WHERE PLUGIN_NAME='validate_password';" || true)"
  local comp; comp="$(run_sql "SELECT COUNT(*) FROM mysql.component WHERE component_urn LIKE 'file://component_validate_password';" || echo 0)"
  if [[ "$st" != "ACTIVE" && "$comp" -eq 0 && "$REMEDIATION" == "YES" ]]; then
    # Try component first (preferred), then plugin
    run_sql "INSTALL COMPONENT 'file://component_validate_password';" || run_sql "INSTALL PLUGIN validate_password SONAME 'validate_password.so';" || true
  fi
  # set sane defaults
  [[ "$REMEDIATION" == "YES" ]] && set_persist "validate_password.length" "14" || true
  [[ "$REMEDIATION" == "YES" ]] && set_persist "validate_password.policy" "1" || true
  local len pol; len="$(mysqld_var 'validate_password.length' || echo 0)"; pol="$(mysqld_var 'validate_password.policy' || echo 0)"
  if [[ "$len" -ge 14 && "$pol" -ge 1 ]]; then emit "7.5" "$t" "PASS" "length=$len policy=$pol"
  else emit "7.5" "$t" "FAIL" "length=$len policy=$pol (recommend len>=14, policy>=1)"; fi
}

c7_6(){
  local t="7.6 No wildcard hostnames"
  local list; list="$(run_sql "SELECT CONCAT(\"'\",user,\"'@'\",host,\"'\") FROM mysql.user WHERE host IN ('%','::','0.0.0.0');" || true)"
  if [[ -z "$list" ]]; then emit "7.6" "$t" "PASS" "no wildcard hosts"
  else
    emit "7.6" "$t" "FAIL" "wildcard host accounts present"
    while IFS= read -r uh; do [[ -z "$uh" ]] && continue
      local u="${uh%%'@'*}"; u="${u#\'}"
      # Generate SQL to clone account onto a safer host then drop wildcard (manual review required):
      append_sql "CREATE USER IF NOT EXISTS ${u}@'${WILDCARD_TARGET_HOST}' IDENTIFIED BY '<set-strong-password>'"
      append_sql "GRANT USAGE ON *.* TO ${u}@'${WILDCARD_TARGET_HOST}'" # Replace with minimal required GRANTS
      append_sql "RENAME USER ${u}@'%' TO ${u}@'${WILDCARD_TARGET_HOST}'"
    done <<<"$list"
    if [[ "$REM_FIX_WILDCARDS" == "YES" && "$REMEDIATION" == "YES" ]]; then
      # ONLY apply if target host provided and you accept the rename risk
      if [[ -n "$WILDCARD_TARGET_HOST" ]]; then run_sql "$(cat "$REM_SQL_OUT")" || true; fi
    fi
  fi
}

c7_7(){
  local t="7.7 No anonymous accounts"
  local c; c="$(run_sql "SELECT COUNT(*) FROM mysql.user WHERE user='' OR user IS NULL;")"
  if [[ "$c" -eq 0 ]]; then emit "7.7" "$t" "PASS" "no anonymous"
  else
    if [[ "$REMEDIATION" == "YES" ]]; then run_sql "DROP USER IF EXISTS ''@'localhost'; DROP USER IF EXISTS ''@'%';" || true; fi
    c="$(run_sql "SELECT COUNT(*) FROM mysql.user WHERE user='' OR user IS NULL;")"
    [[ "$c" -eq 0 ]] && emit "7.7" "$t" "PASS" "anonymous removed" || emit "7.7" "$t" "FAIL" "remaining=$c"
  fi
}

# ------------------------ CH8 Network ----------------------------
c8_1(){
  local t="8.1 require_secure_transport=ON and/or have_ssl=YES"
  local rst; rst="$(mysqld_var 'require_secure_transport' || echo OFF)"
  local ssl; ssl="$(mysqld_var 'have_ssl' || echo NO)"
  if [[ "$rst" == "ON" || "$ssl" == "YES" ]]; then emit "8.1" "$t" "PASS" "require_secure_transport=$rst have_ssl=$ssl"
  else
    [[ "$REMEDIATION" == "YES" ]] && set_persist "require_secure_transport" "ON"
    rst="$(mysqld_var 'require_secure_transport' || echo OFF)"
    [[ "$rst" == "ON" ]] && emit "8.1" "$t" "PASS" "require_secure_transport=ON" || emit "8.1" "$t" "FAIL" "require_secure_transport=$rst have_ssl=$ssl"
  fi
}

c8_2(){
  local t="8.2 Remote users configured with ssl_type (ANY/X509/SPECIFIED)"
  local list; list="$(run_sql "SELECT CONCAT(\"'\",user,\"'@'\",host,\"'\") FROM mysql.user WHERE host NOT IN ('localhost','127.0.0.1','::1') AND (ssl_type IS NULL OR ssl_type='');" || true)"
  if [[ -z "$list" ]]; then emit "8.2" "$t" "PASS" "all remote users have ssl_type"
  else
    emit "8.2" "$t" "FAIL" "remote accounts missing ssl_type"
    while IFS= read -r uh; do [[ -z "$uh" ]] && continue
      append_sql "ALTER USER ${uh//\'/\\\'} REQUIRE SSL"
    done <<<"$list"
    if [[ "$REM_ENFORCE_SSL_REMOTE" == "YES" && "$REMEDIATION" == "YES" ]]; then run_sql "$(cat "$REM_SQL_OUT")" || true; fi
  fi
}

# ------------------------ CH9 Replication ------------------------
c9_2(){
  local t="9.2 SOURCE_SSL_VERIFY_SERVER_CERT=1"
  local v; v="$(mysqld_var 'source_ssl_verify_server_cert' || mysqld_var 'master_ssl_verify_server_cert' || echo 0)"
  if [[ "$v" == "1" || "$v" == "ON" ]]; then emit "9.2" "$t" "PASS" "verify=$v"
  else
    [[ "$REMEDIATION" == "YES" ]] && set_persist "source_ssl_verify_server_cert" "1" || true
    v="$(mysqld_var 'source_ssl_verify_server_cert' || mysqld_var 'master_ssl_verify_server_cert' || echo 0)"
    [[ "$v" == "1" || "$v" == "ON" ]] && emit "9.2" "$t" "PASS" "set" || emit "9.2" "$t" "FAIL" "verify=$v"
  fi
}

c9_3(){
  local t="9.3 master_info_repository=TABLE"
  local v; v="$(mysqld_var 'master_info_repository' || mysqld_var 'source_info_repository' || echo '')"
  if [[ "$v" == "TABLE" ]]; then emit "9.3" "$t" "PASS" "value=$v"
  else
    # Try dynamic if permitted; otherwise emit instruction
    [[ "$REMEDIATION" == "YES" ]] && set_persist "master_info_repository" "'TABLE'" || true
    v="$(mysqld_var 'master_info_repository' || mysqld_var 'source_info_repository' || echo '')"
    if [[ "$v" == "TABLE" ]]; then emit "9.3" "$t" "PASS" "set"
    else
      emit "9.3" "$t" "FAIL" "value=$v"
      append_instr "# Set master_info_repository=TABLE in my.cnf then restart replica:"
      append_instr "[mysqld]"
      append_instr "master_info_repository=TABLE"
      append_instr "# On replica: STOP REPLICA; START REPLICA;"
    fi
  fi
}

c9_4(){
  local t="9.4 Replication users do not have SUPER"
  local list; list="$(run_sql "SELECT DISTINCT GRANTEE FROM information_schema.USER_PRIVILEGES WHERE PRIVILEGE_TYPE='SUPER' AND GRANTEE IN (SELECT CONCAT(\"'\",user,\"'@'\",host,\"'\") FROM mysql.user WHERE user REGEXP 'repl|replica|slave|source');" || true)"
  if [[ -z "$list" ]]; then emit "9.4" "$t" "PASS" "no SUPER on replication users"
  else
    emit "9.4" "$t" "FAIL" "replication users with SUPER"
    while IFS= read -r g; do [[ -z "$g" ]] && continue; append_sql "REVOKE SUPER ON *.* FROM ${g//\'/\\\'}"; done <<<"$list"
    if [[ "$REM_FIX_REPL_SUPER" == "YES" && "$REMEDIATION" == "YES" ]]; then run_sql "$(cat "$REM_SQL_OUT")" || true; fi
  fi
}

# ---------------------- Run ----------------------
main() {
  # Your original list of checks:
  c1_2; c1_3_1_4_1_6; c1_5
  c2_1_4; c2_2_1; c2_7; c2_8; c2_9; c2_12; c2_14; c2_15; c2_16; c2_17; c2_18; c2_19
  c3_1; c3_2; c3_3; c3_4; c3_5; c3_6; c3_7; c3_8
  c4_2; c4_3; c4_5; c4_6; c4_7; c4_8; c4_9; c4_10
  c6_1; c6_2; c6_3; c6_4; c6_audit_enterprise_na
  c7_1; c7_2; c7_3; c7_4; c7_5; c7_6; c7_7
  c8_1; c8_2
  c9_2; c9_3; c9_4

  log "Remediation SQL (if any): $REM_SQL_OUT"
  log "Remediation instructions (if any): $REM_INSTR_OUT"

  # Export summary (CSV only)
  case "$FORMAT" in
    csv) log "CSV saved: $REPORT" ;;
    *)   log "Only CSV supported; saved: $REPORT" ;;
  esac
}
main

