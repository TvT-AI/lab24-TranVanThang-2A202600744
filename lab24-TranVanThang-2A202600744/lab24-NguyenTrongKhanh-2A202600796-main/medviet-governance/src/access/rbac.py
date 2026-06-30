# src/access/rbac.py
import casbin
from functools import wraps
from pathlib import Path
from fastapi import HTTPException, Header
from typing import Optional

# Danh sách user giả lập (production dùng JWT + DB)
MOCK_USERS = {
    "token-alice": {"username": "alice", "role": "admin"},
    "token-bob":   {"username": "bob",   "role": "ml_engineer"},
    "token-carol": {"username": "carol", "role": "data_analyst"},
    "token-dave":  {"username": "dave",  "role": "intern"},
}

ACCESS_DIR = Path(__file__).resolve().parent
enforcer = casbin.Enforcer(
    str(ACCESS_DIR / "model.conf"), str(ACCESS_DIR / "policy.csv")
)

def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    """
    Parse a Bearer token and return the corresponding user.
    Raise HTTPException 401 nếu token không hợp lệ.
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing token")

    scheme, separator, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not separator or not token.strip():
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    user = MOCK_USERS.get(token.strip())

    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    return user

def require_permission(resource: str, action: str):
    """
    Decorator which enforces a Casbin permission.
    Dùng casbin enforcer để check (role, resource, action).
    Raise HTTPException 403 nếu không có quyền.
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Lấy current_user từ kwargs (FastAPI inject qua Depends)
            current_user = kwargs.get("current_user")
            if not current_user:
                raise HTTPException(status_code=401, detail="Missing user context")
            role = current_user["role"]

            allowed = enforcer.enforce(role, resource, action)

            if not allowed:
                raise HTTPException(
                    status_code=403,
                    detail=f"Role '{role}' cannot '{action}' on '{resource}'"
                )
            return await func(*args, **kwargs)
        return wrapper
    return decorator
