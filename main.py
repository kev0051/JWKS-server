# Conda environment: jwks

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
import base64
from datetime import datetime, timedelta
import jwt
import random

app = Flask(__name__)

# Dictionary to store key pairs, key IDs, and expiry timestamps
key_pairs = {}

# Generate a new RSA key-pair with a specified key ID
def generate_rsa_keypair(key_id):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Serialize keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Store the key-pair, key ID, and expiry timestamp in the dictionary
    key_pairs[key_id] = {
        "private_key": private_pem,
        "public_key": public_pem,
        "expiry_timestamp": datetime.now() + timedelta(hours=1)
    }

# RESTful JWKS endpoint that serves the public keys in JWKS format
# GET: http://localhost:8080/.well-known/jwks.json
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    if request.method != 'GET':
        return "Not Acceptable", 406

    jwks_data = {
        "keys": []
    }

    # Iterate through the keys in key_pairs and add them to the JWKS if not expired
    for key_id, key_info in key_pairs.items():
        if key_pairs[key_id]["expiry_timestamp"] > datetime.now():
            public_key_pem = key_info["public_key"]
            public_key = serialization.load_pem_public_key(public_key_pem)
            public_numbers = public_key.public_numbers()

            jwk = {
                "kid": key_id,  # Key ID
                "alg": "RS256",  # Algorithm
                "kty": "RSA",  # Key Type
                "use": "sig",  # Usage (signature)
                "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8'),  # Modulus
                "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).decode('utf-8')  # Exponent
            }

            jwks_data["keys"].append(jwk)

    return jsonify(jwks_data)
    

# /auth endpoint that returns an unexpired, signed JWT on a POST request
# This will return an RS256 Encryption of {"kid": "kidhere", "alg": "RS256"}.{"username": "user", "password": "pass"}.key_pairs[kid]["private_key"]
# POST http://localhost:8080/auth
@app.route('/auth', methods=['POST'])
def auth():
    if request.method != 'POST':
        return "Not Acceptable", 406
    
    # Check if the request has Basic Authentication headers
    if 'Authorization' not in request.headers:
        return "Authentication failed: No Basic Authentication headers provided", 401
    
    # Generate an initial RSA key-pair with a random key ID
    kid = str(random.randint(1, 10000))
    
    # Check if the "expired" query parameter is present
    if 'expired' in request.args:
        # Find an expired key pair, if available
        expired_key = None
        for key_id, key_info in key_pairs.items():
            if key_info["expiry_timestamp"] < datetime.now():
                expired_key = key_id
                break
        
        if expired_key is not None:
            kid = expired_key  # Use the expired key pair's key ID
    
    # Generate or use the key pair associated with the selected key ID
    if kid not in key_pairs:
        generate_rsa_keypair(kid)
    
    auth_header = request.headers['Authorization']
    # The Authorization header value will be in the form 'Basic base64_encoded_credentials'
    # Extract the base64 encoded credentials
    _, base64_credentials = auth_header.split(' ')
    
    # Decode the base64 encoded credentials
    credentials = base64.b64decode(base64_credentials).decode('utf-8')
    
    # Extract the username and password from the credentials and enter into the payload
    username, password = credentials.split(':') 
    payload = {
        'username': username,
        'password': password,
        'exp': key_pairs[kid]["expiry_timestamp"]
    }

    # Get the private key (signature)
    private_key = key_pairs[kid]["private_key"]

    # Get the header
    header = {
        'kid': kid
    }

    # Encode the payload and header into a JWT
    jwt_token = jwt.encode(payload, private_key, algorithm='RS256', headers=header)
    
    return jwt_token


if __name__ == '__main__':

    # Run the server on port 8080
    app.run(debug=True, port=8080)
