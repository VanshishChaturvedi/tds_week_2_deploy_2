import jwt
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI()

# 1. Assigned Constants
ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-ya5fktav.apps.exam.local"
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

# 2. Define the expected request body schema
class TokenRequest(BaseModel):
    token: str

# 3. Verification Endpoint
@app.post("/verify")
async def verify_token(request: TokenRequest):
    try:
        # jwt.decode automatically verifies signature, expiry, audience, and issuer
        decoded_payload = jwt.decode(
            request.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True
            }
        )
        
        # If no exceptions are thrown, the token is perfectly valid
        return {
            "valid": True,
            "email": decoded_payload.get("email"),
            "sub": decoded_payload.get("sub"),
            "aud": decoded_payload.get("aud")
        }
        
    except jwt.PyJWTError:
        # This catches ExpiredSignatureError, InvalidAudienceError, InvalidTokenError, etc.
        return JSONResponse(status_code=401, content={"valid": False})
