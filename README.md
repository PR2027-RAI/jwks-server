# JWKS Server - Project 3
Name: Prasanna Rai
Course: CSCE 3550 - Foundations of Cybersecurity

## About the Project
For Project 3, I added new features to my JWKS server from Project 2. I added AES encryption, user registration, password hashing, authentication logging, and rate limiting. I also divided my code into different files to make it easier to read and understand.


## Features

- Generates RSA keys.
- Encrypts private keys using AES.
- Stores encrypted keys in SQLite.
- Creates valid and expired JWTs.
- Registers new users.
- Generates UUIDv4 passwords.
- Hashes passwords using Argon2.
- Records authentication requests.
- Allows only 10 authentication requests per second per IP.
- Uses safe SQL queries.


## Tools Used
Python, Flask, SQLite, PyJWT, Cryptography, Argon2, Pytest, and autopep8.

## How to Run
Install the required packages:

```bash
python -m pip install -r requirements.txt
```

Set the encryption key in PowerShell for a new database:

```powershell
$env:NOT_MY_KEY = python -c "import secrets; print(secrets.token_hex(32))"
```

Use the same encryption key for an existing database. Do not share or commit the key.

Start the server:

```bash
python app.py
```

The server runs on port 8080.


## Endpoints
- GET /.well-known/jwks.json - Returns valid public keys.
- POST /auth - Returns a valid JWT.
- POST /auth?expired=true - Returns an expired JWT.
- POST /register - Registers a new user.


## Database
I used SQLite to store encrypted private keys, user information, and authentication logs. My database has three tables: keys, users, and auth_logs.


## Testing

I used Pytest and Gradebot to test my project.

Run the automated tests using:

```bash
python -m pytest test_app.py -v --cov=app --cov=database --cov=security --cov=rate_limiter --cov-report=term-missing
```


## Project 3 Results
- 36 tests passed.
- 99% code coverage.
- 99.21% Gradebot score.
- Rate limiting test passed.

I also included screenshots of my test results.


## Previous Project 2 Results
- 11 tests passed.
- 87% code coverage.
- 98.21% Gradebot score.


## Limitations
This project is for learning purposes. The server does not check user passwords during authentication. The rate limiting history is cleared when the server restarts.