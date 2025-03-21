from typing import Dict
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer(auto_error=False)

def get_token_dependency(config: Dict):
    """Return the token dependency if JWT is enabled, else a function that returns None."""
    access_token = config.get("security", {}).get("access_token", False)
    if access_token:
        def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict:
            """Verify the access token from the Authorization header."""
            if credentials:
                bearer_token = credentials.credentials
                if bearer_token == access_token:
                    payload = {"success": True}
                    return payload
            else:
                bearer_token = "(None)"
            raise HTTPException(status_code=401, detail=f"Invalid or expired token {bearer_token}")
        return verify_token
    else:
        return lambda: None
