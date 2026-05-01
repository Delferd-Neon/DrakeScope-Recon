<!-- <img width="1491" height="417" alt="image" src="https://github.com/user-attachments/assets/87ea0e88-7b68-4aec-b359-a79d4b26c58b" />
<img width="1536" height="500" alt="Drake scope recon" src="https://github.com/user-attachments/assets/abcd0e06-081e-4086-9cd7-021d5c13f2c8" /> -->
<!-- <img width="612" height="408" alt="Drake_scope_recon-removebg-preview" src="https://github.com/user-attachments/assets/ef41ed59-e7a3-4d75-b1c2-3b6990ad1f27" -->
<img width="1536" height="1024" alt="DrakeRecon logo-Photoroom" src="https://github.com/user-attachments/assets/12d445f8-7037-41b5-8251-0ec1c40d16d0" />


# DrakeScope Recon

DrakeScope Recon is a small web dashboard for authorized directory and subdomain enumeration. It blocks scans unless the requested host is present in the local SQLite allowlist.

## Run

```powershell
python server.py --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`.

To require a token before anyone can add or update allowed targets:

```powershell
$env:ASM_ADMIN_TOKEN = "change-me"
python server.py --host 127.0.0.1 --port 8000
```

For public or LAN binds, an admin token is required and must be at least 16 characters:

```powershell
$env:DRAKESCOPE_ADMIN_TOKEN = "use-a-long-random-token"
python server.py --host 0.0.0.0 --port 8000
```

To seed a target at startup:

```powershell
python server.py --allow example.com
```

For a local lab only, you can disable the allowlist gate on loopback:

```powershell
$env:DRAKESCOPE_REQUIRE_ALLOWLIST = "false"
python server.py --host 127.0.0.1 --port 8000
```

Private, loopback, reserved, and link-local scan targets are blocked by default. Enable them only for local lab work:

```powershell
$env:DRAKESCOPE_ALLOW_PRIVATE_TARGETS = "true"
```

## Safety model

- Directory scans accept `http` and `https` URLs only.
- Subdomain scans require the base domain to be explicitly present in the allowlist.
- Directory scans may include subdomains only when the stored allowlist row has `allow_subdomains` enabled.
- Public binds require an admin token before the server starts.
- Unrestricted mode is only allowed on localhost/loopback binds.
- Private/reserved network targets and proxies are blocked unless `DRAKESCOPE_ALLOW_PRIVATE_TARGETS=true`.
- Wordlists are capped at 2,000 entries per scan.
- Users can paste extra candidates or upload a `.txt` wordlist from the dashboard.
- Probe concurrency is user-configurable, capped at 16 workers, with short timeouts.
- Optional HTTP/HTTPS proxy support is available for directory probes. DNS-based subdomain enumeration does not use the proxy.
- The dashboard also supports a `Both (parallel)` mode to run directory + subdomain enumeration at the same time.

Use this only for systems you own or have written permission to test.
