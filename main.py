from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import jwt  # this is the PyJWT library

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-8z24thqx.apps.exam.local"

app = FastAPI()


@app.post("/verify")
async def verify(request: Request):
    try:
        body = await request.json()
        token = body["token"]

        claims = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],        # only accept RS256
            audience=AUDIENCE,           # checks aud
            issuer=ISSUER,               # checks iss
            options={"require": ["exp", "iss", "aud"]},  # these must exist
        )
    except Exception:
        # bad JSON, missing token, bad signature, expired, wrong aud/iss...
        return JSONResponse(status_code=401, content={"valid": False})

    return {
        "valid": True,
        "email": claims.get("email"),
        "sub": claims.get("sub"),
        "aud": AUDIENCE,
    }