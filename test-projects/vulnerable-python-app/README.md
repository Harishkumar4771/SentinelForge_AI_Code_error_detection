# vulnerable-python-app

**Deliberately insecure.** This is the demo target for SentinelForge.

It contains controlled, textbook vulnerability classes and **no** destructive
or malicious functionality: nothing here exfiltrates data, damages a host, or
reaches the network. It is meant to be analysed and scanned, never deployed.

| Flaw | Location | Class |
|---|---|---|
| SQL injection | `database.py` | CWE-89 |
| Hardcoded secrets | `config.py` | CWE-798 |
| Weak auth (unsalted MD5, predictable tokens) | `auth.py` | CWE-328 / CWE-330 |
| Path traversal | `files.py` | CWE-22 |
| Missing authorization | `app.py` (`/api/admin/*`) | CWE-862 |
| Business logic bugs | `billing.py` | CWE-840 |
| Insufficient input validation | `app.py` (`/api/validate-email`) | CWE-20 |
| Insecure deserialization | `session.py` | CWE-502 |
| Insecure crypto config | `config.py` | CWE-327 |
| Outdated dependencies | `requirements.txt` | CWE-1104 |

Run locally on loopback only:

```bash
pip install -r requirements.txt
python app.py     # http://127.0.0.1:5001
```
