# 8TechBank — Security Assessment

## BSE 4202: Software Security Practical Assignment

### Group BSE26-9 | Makerere University | May 2026

## Overview

**8TechBank** is a simulated online banking web application built with Python and
Flask, developed for a software security practical assignment. It demonstrates
common web application vulnerabilities and their corresponding fixes by shipping
the same banking system in two side-by-side builds:

- **Vulnerable build** (port 5000) — deliberately insecure, exposing SQL injection,
  reflected and stored cross-site scripting (XSS), cross-site request forgery
  (CSRF), insecure direct object references (IDOR), weak password storage, and
  missing security headers.
- **Secure build** (port 5001) — the hardened version that remediates every flaw
  using parameterised queries, output escaping, anti-CSRF tokens, ownership and
  authorisation checks, bcrypt password hashing, security headers, and a
  JWT-authenticated API protected by rate limiting.

The application simulates core banking features — user registration and login,
account dashboards, fund transfers, transaction history, and an admin panel — so
each vulnerability can be exploited against the vulnerable build and shown to be
blocked on the secure build. Accompanying exploits, evidence screenshots, and a
formal security assessment report document the findings and remediation.

> **Note:** 8TechBank is a teaching artefact intended only for local, isolated
> security testing. It must never be deployed to a public or production
> environment.

The full assignment brief this project implements — *SecureApp: Build, Break, and
Fix — A Full-Stack Security Assessment* — is included at
[docs/BSE4202_Software_Security_Assignment_Brief.pdf](docs/BSE4202_Software_Security_Assignment_Brief.pdf).
It defines the five tasks: (1) security audit, (2) exploit demonstration,
(3) secure code implementation, (4) API security & sandboxing, and (5) the
security assessment report.

## Group Members

- Kitonsa Elvis - 20/U/7785/PS
- Katuramu Edgar - 22/U/21756/PS
- Asiimire Patricia - 21/U/19271/PS
- Kizito Daniel Jr. - 19/U/8282/EVE

## Project Structure

    8TechBank/
    ├── src/
    │   ├── vulnerable/     <- Deliberately vulnerable app (port 5000)
    │   ├── secure/         <- Fixed secure app (port 5001)
    │   └── requirements.txt
    ├── exploits/           <- CSRF attack proof-of-concept files
    ├── screenshots/        <- All evidence screenshots
    ├── report/             <- Security assessment report and documents
    ├── docs/               <- Assignment brief (BSE 4202)
    ├── Dockerfile
    ├── docker-compose.yml
    └── README.md

## Setup Instructions

### Prerequisites

- Python 3.10 or higher
- pip

### Installation

    # Navigate to project folder
    cd 8TechBank

    # Create virtual environment
    python -m venv venv

    # Activate virtual environment (Windows)
    venv\Scripts\activate

    # Install dependencies
    pip install -r src/requirements.txt

### Running the Vulnerable App (Tasks 1 and 2)

    cd src/vulnerable
    python app.py
    # Visit http://127.0.0.1:5000

### Running the Secure App (Tasks 3 and 4)

    cd src/secure
    python app.py
    # Visit http://127.0.0.1:5001

## Test Credentials

| Username | Password    | Role  |
| -------- | ----------- | ----- |
| alice    | password123 | user  |
| bob      | qwerty456   | user  |
| admin    | admin123    | admin |

## Testing the API (Secure App Only)

Get a JWT token:

    Invoke-WebRequest -Uri "http://127.0.0.1:5001/api/auth/token" -Method POST -ContentType "application/json" -Body '{"username":"alice","password":"password123"}' | Select-Object -ExpandProperty Content

Access protected endpoint (replace TOKEN with actual token):

    Invoke-WebRequest -Uri "http://127.0.0.1:5001/api/account" -Method GET -Headers @{Authorization="Bearer TOKEN"} | Select-Object -ExpandProperty Content

Test rate limiting (run 6 times to trigger 429):

    Invoke-WebRequest -Uri "http://127.0.0.1:5001/api/auth/token" -Method POST -ContentType "application/json" -Body '{"username":"wrong","password":"wrong"}' | Select-Object -ExpandProperty Content

## Exploit Files

| File                             | Description                                        |
| -------------------------------- | -------------------------------------------------- |
| exploits/csrf_attack.html        | CSRF attack against vulnerable app (port 5000)     |
| exploits/csrf_attack_secure.html | CSRF attack attempt against secure app (port 5001) |

Open these files directly in Chrome while authenticated to demonstrate the attack.

## Ethical Notice

All exploit demonstrations were conducted exclusively against
the locally hosted 8TechBank application running on localhost.
No real systems were targeted. All testing complies with
Uganda's Computer Misuse Act, 2011.
