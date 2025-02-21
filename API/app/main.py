from os import getenv

from fastapi import FastAPI, Depends, HTTPException, status
from jwcrypto.common import JWException
from keycloak import KeycloakOpenID
from fastapi.security import HTTPBearer
from starlette.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Configure client
keycloak_openid = KeycloakOpenID(
    server_url=getenv("KEYCLOAK_URL"),
    client_id=getenv("KEYCLOAK_CLIENT_ID"),
    realm_name=getenv("KEYCLOAK_REALM"),
    client_secret_key=getenv("KEYCLOAK_CLIENT_SECRET_KEY")
)

security = HTTPBearer()

def decode_token(token: str = Depends(security)) -> dict:
    try:
        return keycloak_openid.decode_token(token.credentials, validate=True)
    except JWException:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
    )


def check_reports_permissions(token: str = Depends(security)):
    token_data = decode_token(token)
    if 'prothetic_user' not in token_data['realm_access']['roles']:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have enough permissions",
            headers={"WWW-Authenticate": "Bearer"},
        )



@app.get("/reports", dependencies=[Depends(check_reports_permissions)])
def root():
    return 'Fake data'


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
