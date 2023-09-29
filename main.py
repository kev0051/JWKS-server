from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import base64

app = Flask(__name__)
CORS(app)

# Secret key for JWT token generation
SECRET_KEY = 'secret'

# Generate an RSA key pair for JWT validation
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

public_key = private_key.public_key()

# Convert n and e to base64url-encoded strings
n_bytes = public_key.public_numbers().n.to_bytes(256, byteorder='big')
e_bytes = public_key.public_numbers().e.to_bytes(4, byteorder='big')

n_base64 = base64.urlsafe_b64encode(n_bytes).rstrip(b'=').decode('utf-8')
e_base64 = base64.urlsafe_b64encode(e_bytes).rstrip(b'=').decode('utf-8')

# Dummy user data
user_data = {
    "username": "userABC",
    "password": "password123"
}

@app.route('/auth', methods=['POST'])
def authenticate():
    expired = request.args.get('expired', False)

    if expired:
        # Generate an expired JWT token with an expiration time in the past
        now = datetime.utcnow()
        expired_time = now - timedelta(minutes=300)
        payload = {
            "username": user_data["username"],
            "password": user_data["password"],
            "exp": int(expired_time.timestamp()),  # Set expiration time in the past
            "iat": int(now.timestamp()),
        }
        token = jwt.encode(payload, private_key, algorithm='RS256', headers={"kid": "your_kid"})
    else:
        # Generate a valid JWT token
        payload = {
            "username": user_data["username"],
            "password": user_data["password"],
            "exp": int((datetime.utcnow() + timedelta(minutes=30)).timestamp()),
            "iat": int(datetime.utcnow().timestamp()),
        }
        token = jwt.encode(payload, private_key, algorithm='RS256', headers={"kid": "your_kid"})

    return token

@app.route('/.well-known/jwks.json')
def jwks():
    jwks_data = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "your_kid",  # Ensure kid matches the one in JWT header
                "use": "sig",
                "n": n_base64,
                "e": e_base64,
            }
        ]
    }
    return jsonify(jwks_data)

if __name__ == '__main__':
    app.run(port=8080)
