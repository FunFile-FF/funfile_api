# FunFile API CLI

A modular Python command-line client for interacting with the FunFile API.

Currently supports managing seedbox IPs with HMAC authentication.

Designed to be expandable for future API modules.

---

### FEATURES

- HMAC-SHA256 request signing
- Config file support
- CLI override for credentials
- Automatic public IP detection
- Modular architecture for future expansion
- Clean JSON output

---

### REQUIREMENTS

- Python 3.8+
- requests library

Install dependency:
```
pip install requests
```
---

### CONFIGURATION

Create a file named config.json in the same directory as funfile.py:
```
{
  "api_key": "YOUR_PUBLIC_API_KEY",
  "secret": "YOUR_SECRET_KEY",
  "base_url": "https://www.funfile.org/api"
}
```

You may override values via CLI flags:

- --api-key
- --secret
- --base-url

---

### AUTHENTICATION

All requests are signed using these headers:
```
X-API-Key
X-Timestamp
X-Signature
```
### Signature format:

#### GET requests:
```
HMAC_SHA256(timestamp)
```

#### POST requests:
```
HMAC_SHA256(timestamp + body)
```

The secret key is never sent to the API.
It is only used locally to compute the HMAC signature.

---

## USAGE

General syntax:
```
python funfile.py <module> <action> [options]
```
---

### SEEDBOX IP MANAGEMENT

Module name:
```
seedboxip
```
---

### LIST IPS
```
python funfile.py seedboxip list
```
---

### ADD IP(S)

Single IP:
```
python funfile.py seedboxip add --ips 1.2.3.4
```
Multiple IPs:
```
python funfile.py seedboxip add --ips 1.2.3.4,2001:db8::1
```
Auto-detect your current public IP:
```
python funfile.py seedboxip add
```
---

### REMOVE IP(S)
```
python funfile.py seedboxip remove --ips 1.2.3.4
```
---

### REPLACE ALL IPS
```
python funfile.py seedboxip replace --ips 1.2.3.4,5.6.7.8
```
---

### COMMAND LINE OVERRIDES

Example:
```
python funfile.py seedboxip list --api-key YOUR_KEY --secret YOUR_SECRET
```
---

### PROJECT STRUCTURE
```
funfile.py
config.json
README.md
```
Future modular structure:
```
modules/
    seedboxip.py
    user.py
    torrent.py
```
---

### EXAMPLE OUTPUT
```
Status: 200

{
  "seedbox_ips": [
    "1.2.3.4",
    "2001:db8::1"
  ]
}
```
---

### ERROR HANDLING

The CLI prints:

- HTTP status code
- JSON response body
- Raw response if JSON decoding fails

---

### SECURITY NOTES

- The secret key is never transmitted
- HMAC signing happens locally
- Do NOT commit config.json to public repositories
- Consider environment variables in production

---

### LICENSE

GNU General Public License v3.0.  
See LICENSE for more details.


