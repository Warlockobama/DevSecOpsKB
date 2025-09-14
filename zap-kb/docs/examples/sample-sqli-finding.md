---
findingId: fin-d1a7e8b9
definitionId: def-40018
pluginId: "40018"
name: "SQL Injection - /api/v1/users"
url: "https://my-app.com/api/v1/users"
method: "GET"
tags:
  - zap-kb
scan:
  label: "Run 2025-08-19"
  source: "zap"
domain:
  label: "my-app"
  url: "https://my-app.com"
status:
  open: 3
  triaged: 0
  fp: 0
  accepted: 0
  fixed: 0
severity:
  level: "High"
  numeric: 3
---

# 🔴 High: SQL Injection

> [!abstract] Summary
> - **Finding:** `SQL Injection`
> - **URL:** `https://my-app.com/api/v1/users`
> - **Method:** `GET`
> - **Domain:** `my-app`
> - **Occurrences:** 3

---

## Occurrences

| ID                                       | URL Path          | Parameter | Attack Snippet      | Status |
| ---------------------------------------- | ----------------- | --------- | ------------------- | ------ |
| [[occ-a1b2c3d4\|occ-a1b2c3d4]] | `/api/v1/users`   | `id`      | `1' OR '1'='1`     | open   |
| [[occ-e5f6g7h8\|occ-e5f6g7h8]] | `/api/v1/users`   | `id`      | `1; SELECT pg_sleep(10)--` | open   |
| [[occ-9c0d1e2f\|occ-9c0d1e2f]] | `/api/v1/users`   | `id`      | `1 UNION SELECT 1,2,version()--` | open   |

<br>

---

## Remediation

> [!bug] Triage Guidance
> - **Confirm:** Use the `curl` command from an occurrence to confirm the response delay or error. A 10-second delay for the time-based attack is a strong indicator.
> - **Parameterize:** This is a classic SQLi vulnerability. The application is not using parameterized queries (prepared statements).
> - **Impact:** High. An attacker can likely exfiltrate, modify, or delete any data in the database.

**General Guidance**
The application should use parameterized queries or prepared statements. This ensures that user input is treated as data, not as executable code. Avoid building SQL queries by concatenating strings with user input. Use an ORM or a database library that enforces this practice.

For numeric inputs, always validate and sanitize the data, ensuring it conforms to the expected type and range.

---

## Details

**Description**
SQL injection may be possible in the parameter. The attack was based on dynamic string building, which is not safe.

**Solution**
Do not build dynamic SQL queries. Use a safe API which avoids the use of the interpreter, or provides contextual escaping. The preferred option is to use a parameterized query.

---

## References
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP: SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP Cheat Sheet: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
