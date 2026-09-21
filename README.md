#JWKS Server Project

This is my Project 1 for CSCE 3550. I created a basic JWKS server using Python and Flask.

The server:
-Runs on port 8080
- Provides public keys through the JWKS endpoint
- Creates valid JWTs
- Creates expired JWTs when requested

## Run
python app.py

##Test
pytest --cov=app --cov-report=term-missing

##Author
Prasanna Rai
