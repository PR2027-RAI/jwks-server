# JWKS Server - Project 2

**Name:** Prasanna Rai  
**Course:** CSCE 3550 - Foundations of Cybersecurity

## About the Project
For Project 2, I updated my JWKS server from Project 1 by adding SQLite. The server now saves private keys in a database instead of only keeping them in memory. I used Python and Flask to generate JWT tokens and return public keys.

## Features
- Generates RSA keys
- Stores private keys in SQLite
- Creates valid and expired JWTs
- Returns valid public keys
- Uses safe SQL queries

## Tools Used

Python, Flask, SQLite, PyJWT, Cryptography, and Pytest.

## How to Run

Install the packages:

```bash
python -m pip install flask pyjwt cryptography pytest pytest-cov
```

Start the server:

```bash
python app.py
```

The server runs on port 8080.

## Endpoints

- `GET /.well-known/jwks.json` - Returns valid public keys
- `POST /auth` - Returns a valid JWT
- `POST /auth?expired=true` - Returns an expired JWT

## Database
I used SQLite to store private keys, key IDs, and expiration times. The database is created when the server starts.

## Testing
I used Pytest and Gradebot to test my project.

Run the tests using:

```bash
python -m pytest test_app.py -v --cov=app --cov-report=term-missing
```

## Results

- 11 tests passed
- 87% test coverage
- 98.21% Gradebot score

I also included screenshots of my test results.
