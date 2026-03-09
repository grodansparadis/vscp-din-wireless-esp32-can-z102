# Test code for the Websocket interface

This folder contains files for websocket tests

See also the top-level firmware README: [../../README.md](../../README.md)

## mintest_ws1.html
Simplest possible login test for VSCP ws1 websocket interface.

## test_ws1.py
Python (ver 3) code to login on the websocket interface and perform
some VSCP ws1 websocket commands and then wait for incoming events. User, password and key should be set to default values.

## test_ws2.py
Python (ver 3) code to login on the websocket interface and perform
some VSCP ws2 websocket commands and then wait for incoming events. User, password and key should be set to default values.

## test_ws1.js
node.js code to login on the websocket interface and perform
some VSCP ws1 websocket commands and then wait for incoming events. User, password and key should be set to default values.

## test_ws2.js
node.js code to login on the websocket interface and perform
some VSCP ws2 websocket commands and then wait for incoming events. User, password and key should be set to default values.

## AUTH encryption (JS and Python scripts)

`test_ws1.js`, `test_ws2.js`, `test_ws1.py`, and `test_ws2.py` now build `AUTH` dynamically using:

- AES-128-CBC
- IV = received SID (from connect response / challenge)
- Encrypted payload = `username;password`

Credential/key sources (highest to lowest):

1. CLI options: `--user`, `--password`, `--key`
2. WS-specific env vars: `WS1_USERNAME`/`WS2_USERNAME`, `WS1_PASSWORD`/`WS2_PASSWORD`, `WS1_KEY`/`WS2_KEY`
3. Generic env vars: `VSCP_USERNAME`, `VSCP_PASSWORD`, `VSCP_KEY16`
4. Defaults: `admin`, `secret`, `A4A86F7D7E119BA3F0CD06881E371B98`

Examples:

- `node test_ws1.js --url ws://192.168.1.50:8884/ws1 --user admin --password secret --key A4A86F7D7E119BA3F0CD06881E371B98`
- `WS2_URL=ws://192.168.1.50:8884/ws2 WS2_USERNAME=admin WS2_PASSWORD=secret WS2_KEY=A4A86F7D7E119BA3F0CD06881E371B98 node test_ws2.js`
- `python test_ws1.py --url ws://192.168.1.50:8884/ws1 --user admin --password secret --key A4A86F7D7E119BA3F0CD06881E371B98`
- `WS2_URL=ws://192.168.1.50:8884/ws2 WS2_USERNAME=admin WS2_PASSWORD=secret WS2_KEY=A4A86F7D7E119BA3F0CD06881E371B98 python test_ws2.py`

### Quick start auth test

```bash
# WS1 (Node.js)
node test_ws1.js --url ws://192.168.1.50:8884/ws1 --user admin --password secret --key A4A86F7D7E119BA3F0CD06881E371B98

# WS2 (Node.js)
node test_ws2.js --url ws://192.168.1.50:8884/ws2 --user admin --password secret --key A4A86F7D7E119BA3F0CD06881E371B98

# WS1 (Python)
python test_ws1.py --url ws://192.168.1.50:8884/ws1 --user admin --password secret --key A4A86F7D7E119BA3F0CD06881E371B98

# WS2 (Python)
python test_ws2.py --url ws://192.168.1.50:8884/ws2 --user admin --password secret --key A4A86F7D7E119BA3F0CD06881E371B98
```

### Python AES backend note

The Python scripts print the AES backend at startup:

- `AES backend : cryptography`
- `AES backend : pycryptodome`
- `AES backend : missing (install cryptography or pycryptodome)`

If backend is missing, install one of:

- `pip install cryptography`
- `pip install pycryptodome`

## URL override for all CLI test scripts

The following scripts support URL override:

- `test_ws1.js`
- `test_ws2.js`
- `test_ws1.py`
- `test_ws2.py`

URL source precedence (highest to lowest):

1. `--url <url>`
2. `--url=<url>`
3. Positional URL argument
4. Environment variable (`WS1_URL` or `WS2_URL`)
5. Script built-in default URL

Examples:

- `node test_ws1.js --url ws://192.168.1.50:8884/ws1`
- `WS2_URL=ws://192.168.1.50:8884/ws2 node test_ws2.js`
- `python test_ws1.py ws://192.168.1.50:8884/ws1`
- `WS2_URL=ws://192.168.1.50:8884/ws2 python test_ws2.py`