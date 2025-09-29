mkdir -p docs
cat > docs/README-ce84.md <<'EOF'
# CIS MySQL Community Server 8.4 Benchmark (Automated Checks)

## Purpose
Implements **CIS Oracle MySQL Community Server 8.4 Benchmark v1.0.0** (Automated checks).  
Now supports **full remediation for all feasible Automated controls**, with **audit-first** default and **explicit flags** for higher-risk changes.

---

## Features
- **Audit-first**: No changes unless `REMEDIATION=YES`.
- **Full remediation coverage**:
  - Dynamic settings via `SET PERSIST`.
  - Startup-only settings → `remediation_instructions.txt`.
  - Account/schema changes → `remediation.sql`.
- **Granular control** via environment flags for risky actions.
- **Profiles & scope**: `--profile L1|L2`, `--scope linux|rdbms`.
- **Reports**:
  - `cis_ce84_report.csv` — PASS/FAIL/N/A/INFO.
  - `remediation.sql` — ALTER/REVOKE/DROP statements.
  - `remediation_instructions.txt` — my.cnf snippets & ops notes.

---

## Requirements
- MySQL client (`mysql`) with secure auth (e.g., `--login-path`).
- MySQL user with:
  - `SYSTEM_VARIABLES_ADMIN`, `SESSION_VARIABLES_ADMIN`, `CONNECTION_ADMIN`
  - Read on `mysql.*`, `performance_schema`, `information_schema`.
- OS tools: `bash`, `stat`, `awk`, `grep`, `df`, `sudo`.

---

## Usage

### Audit only
```bash
./scripts/check_rules_ce84_full.sh \
  --profile L2 \
  --scope linux \
  --mysql-opts "--login-path=prod84"


