# Test the dashboard with the local demo

Open two PowerShell windows in C:\SentinelAPI.

Window 1 ? API to test:
```powershell
.\.venv\Scripts\python -m uvicorn demo_api:app --host 127.0.0.1 --port 8000
```

Window 2 ? dashboard:
```powershell
.\.venv\Scripts\python -m sentinelapi.web
```

Open http://127.0.0.1:8766, select Your API, enter http://127.0.0.1:8000, upload examples/demo-openapi.json, use request limit 150 and requests/second 20, then click Run security scan.

The specification describes the bundled demo; it does not run a server by itself. The demo deliberately contains vulnerabilities. Review findings for /users/search, /greet and /files, expand View evidence, and download HTML. Open http://127.0.0.1:8000/docs to explore the API directly. Stop both servers with Ctrl+C in their respective windows. If either port is in use, select a free port and update the corresponding browser URL/base URL.
