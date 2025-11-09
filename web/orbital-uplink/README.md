# Orbital Uplink

## What is this challenge about?

This challenge simulates a secure-looking space mission uplink system called **Orbital Uplink**, where astronauts upload PDF mission documents for preview.  
Hidden within the app is a privilege escalation path that allows an authenticated non-admin user to access restricted files (like `/flag.txt`) intended for admin-only access.  

The vulnerability chain includes:
- **Privilege escalation** from non-admin to admin using parameter injection.
- **Improper access control** on file preview functionality.
- **Misconfigured server environment** exposing sensitive files.


Contestants are expected to:
1. Explore the web interface for file upload and preview functionality.
2. Identify how to bypass restrictions to preview arbitrary files.
3. Locate and retrieve the hidden flag stored outside the web root.

---

## Difficulty Level

**Easy** — The app’s UI is simple and approachable, but the intended exploit requires understanding basic file handling vulnerabilities and using crafted requests to bypass server-side checks.  
The challenge does not require deep reverse engineering but demands careful observation and testing.

---

## Time

Estimated **10–30 minutes** 

---

## Fun

The challenge is designed to feel rewarding:
- A clear "aha!" moment when discovering the bypass.
- Avoids brute-force-heavy tasks — focuses on logic and observation.

---

## Tools

- Browser developer tools (to inspect requests/responses).
- `curl` or equivalent HTTP client for crafting custom requests.
---

## Artifacts

Included:
- Dockerfile and application source code
- `flag.txt`

---

## Special Considerations / Infrastructure requirements
- The challenge must run inside an isolated Docker container.
- Contestants will be provided only with the IP address and port to connect; no source files or additional resources will be shared.
