import logging
import os
import re
from enum import Enum
from typing import Any, Optional, List, Union

import httpx
from bson import ObjectId
from bson.errors import InvalidId
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator

from keycloak_auth.auth import decode_keycloak_token
from keycloak_auth.user_mapping import resolve_or_create_local_user_async

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

load_dotenv(dotenv_path=".env")

root_path = os.getenv("ROOT_PATH", "/user-management-api")

app = FastAPI(
    title="User Management Service API",
    description="DIPS User Management Service API",
    version="1.0",
    root_path=root_path,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MONGO_USER = os.getenv("MONGO_USER")
MONGO_PASSWORD = os.getenv("MONGO_PASSWORD")
MONGO_HOST = os.getenv("MONGO_HOST", "localhost")
MONGO_PORT = os.getenv("MONGO_PORT")
MONGO_DB = os.getenv("MONGO_DB", "dips_services")

KEYCLOAK_BASE_URL = (os.getenv("KEYCLOAK_BASE_URL") or "").rstrip("/")
KEYCLOAK_REALM = (os.getenv("KEYCLOAK_REALM") or "").strip()

KEYCLOAK_CLIENT_SECRET = (os.getenv("KEYCLOAK_CLIENT_SECRET") or "").strip()
KEYCLOAK_CLIENT_ID = (os.getenv("KEYCLOAK_CLIENT_ID") or "").strip()
KEYCLOAK_ISSUER = (os.getenv("KEYCLOAK_ISSUER") or "").rstrip("/")
KEYCLOAK_JWKS_URL = (os.getenv("KEYCLOAK_JWKS_URL") or "").strip()
KEYCLOAK_AUDIENCE = (os.getenv("KEYCLOAK_AUDIENCE") or "").strip()
KEYCLOAK_ALGORITHMS = [
    algo.strip()
    for algo in (os.getenv("KEYCLOAK_ALGORITHMS") or "RS256").split(",")
    if algo.strip()
]

KEYCLOAK_ADMIN_REALM = (os.getenv("KEYCLOAK_ADMIN_REALM") or "master").strip()
KEYCLOAK_ADMIN_CLIENT_ID = (os.getenv("KEYCLOAK_ADMIN_CLIENT_ID") or "admin-cli").strip()
KEYCLOAK_ADMIN_CLIENT_SECRET = (os.getenv("KEYCLOAK_ADMIN_CLIENT_SECRET") or "").strip()
KEYCLOAK_ADMIN_USERNAME = (os.getenv("KEYCLOAK_ADMIN_USERNAME") or "").strip()
KEYCLOAK_ADMIN_PASSWORD = (os.getenv("KEYCLOAK_ADMIN_PASSWORD") or "").strip()

if MONGO_PORT:
    MONGO_PORT = int(MONGO_PORT)
    MONGO_URI = f"mongodb://{MONGO_USER}:{MONGO_PASSWORD}@{MONGO_HOST}:{MONGO_PORT}"
else:
    MONGO_URI = (
        f"mongodb+srv://{MONGO_USER}:{MONGO_PASSWORD}@{MONGO_HOST}/"
        "?retryWrites=true&w=majority&appName=Cluster0"
    )

client = AsyncIOMotorClient(MONGO_URI)
db = client[MONGO_DB]
users_collection = db.users

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/user/login/")
oauth2_scheme_optional = OAuth2PasswordBearer(tokenUrl="/user/login/", auto_error=False)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class PartyType(str, Enum):
    CONSUMER = "consumer"
    PROVIDER = "provider"


class MongoObject(BaseModel):
    id: Optional[object] = Field(None, alias="_id")

    @field_validator("id")
    def process_id(cls, value):
        if isinstance(value, ObjectId):
            return str(value)
        return value


class User(MongoObject):
    keycloak_sub: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    name: Optional[str] = None
    username: Optional[str] = None
    type: Optional[PartyType] = None
    username_email: Optional[EmailStr] = None
    password: Optional[str] = Field(default=None)
    organization: Optional[Union[List[str], str]] = Field(default=None)
    incorporation: Optional[str] = Field(default=None)
    address: Optional[str] = Field(default=None)
    vat_no: Optional[str] = Field(default=None)
    position_title: Optional[str] = Field(default=None)
    phone: Optional[str] = Field(default=None)

    @model_validator(mode="before")
    @classmethod
    def sync_name_fields(cls, values):
        if not isinstance(values, dict):
            return values

        first_name = (values.get("first_name") or "").strip()
        last_name = (values.get("last_name") or "").strip()
        name = (values.get("name") or "").strip()
        username = (values.get("username") or "").strip()
        values["username"] = username or None

        if first_name or last_name:
            values["first_name"] = first_name or None
            values["last_name"] = last_name or None
            values["name"] = " ".join(part for part in [first_name, last_name] if part) or None
        elif name:
            parts = name.split(None, 1)
            values["first_name"] = parts[0]
            values["last_name"] = parts[1] if len(parts) > 1 else None
            values["name"] = name

        return values


class UserDetailsUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    name: Optional[str] = None
    username: Optional[str] = None
    type: Optional[PartyType] = None
    username_email: Optional[EmailStr] = None
    # password: Optional[str] = Field(default=None)
    organization: Optional[Union[List[str], str]] = Field(default=None)
    incorporation: Optional[str] = Field(default=None)
    address: Optional[str] = Field(default=None)
    vat_no: Optional[str] = Field(default=None)
    position_title: Optional[str] = Field(default=None)
    phone: Optional[str] = Field(default=None)


class UserUpdatePassword(BaseModel):
    user_id: Optional[str] = None
    keycloak_sub: Optional[str] = None
    username_email: Optional[EmailStr] = None
    password: Optional[str] = Field(default=None)




def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def _mask_password(user_dict: dict[str, Any]) -> dict[str, Any]:
    user_dict = dict(user_dict)
    user_dict["password"] = None
    if isinstance(user_dict.get("_id"), ObjectId):
        user_dict["_id"] = str(user_dict["_id"])
    return user_dict


def normalize_org(org: Optional[Union[List[str], str]]) -> Optional[List[str]]:
    if org is None:
        return None
    if isinstance(org, list):
        return [x.strip() for x in org if isinstance(x, str) and x.strip()]
    if isinstance(org, str):
        return [x.strip() for x in org.split(",") if x.strip()]
    return None


def _clean_optional_string(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    value = value.strip()
    return value or None


def _compose_name(first_name: Optional[str], last_name: Optional[str]) -> Optional[str]:
    return " ".join(part for part in [first_name, last_name] if part) or None


def _keycloak_attr_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, Enum):
        value = value.value
    if isinstance(value, list):
        normalized_items = []
        for item in value:
            if isinstance(item, Enum):
                item = item.value
            item = str(item).strip()
            if item:
                normalized_items.append(item)
        return normalized_items
    value = str(value).strip()
    return [value] if value else []


async def _find_user(
    user_id: Optional[str],
    user_email: Optional[str],
    keycloak_sub: Optional[str] = None,
) -> dict[str, Any]:
    user_by_id = None
    user_by_email = None
    user_by_keycloak_sub = None

    if user_id:
        try:
            user_by_id = await users_collection.find_one({"_id": ObjectId(user_id)})
        except InvalidId as exc:
            raise HTTPException(status_code=400, detail="Invalid user id") from exc
        if user_by_id is None:
            raise HTTPException(status_code=404, detail="User not found")

    if user_email:
        user_by_email = await users_collection.find_one({"username_email": user_email})
        if user_by_email is None:
            raise HTTPException(status_code=404, detail="User not found")

    if keycloak_sub:
        user_by_keycloak_sub = await users_collection.find_one({"keycloak_sub": keycloak_sub})
        if user_by_keycloak_sub is None:
            raise HTTPException(status_code=404, detail="User not found")

    if user_by_id and user_by_email and user_by_id["_id"] != user_by_email["_id"]:
        raise HTTPException(
            status_code=400,
            detail="user_id and user_email refer to different users",
        )

    if user_by_id and user_by_keycloak_sub and user_by_id["_id"] != user_by_keycloak_sub["_id"]:
        raise HTTPException(
            status_code=400,
            detail="user_id and keycloak_sub refer to different users",
        )

    if user_by_email and user_by_keycloak_sub and user_by_email["_id"] != user_by_keycloak_sub["_id"]:
        raise HTTPException(
            status_code=400,
            detail="user_email and keycloak_sub refer to different users",
        )

    user = user_by_id or user_by_email or user_by_keycloak_sub
    if user is None:
        raise HTTPException(
            status_code=400,
            detail="Either user_id, user_email, or keycloak_sub is required",
        )
    return user


async def _find_user_for_password_update(
    user_id: Optional[str],
    user_email: Optional[str],
    keycloak_sub: Optional[str],
) -> dict[str, Any]:
    users: list[dict[str, Any]] = []

    if user_id:
        try:
            user_by_id = await users_collection.find_one({"_id": ObjectId(user_id)})
        except InvalidId as exc:
            raise HTTPException(status_code=400, detail="Invalid user id") from exc
        if user_by_id is None:
            raise HTTPException(status_code=404, detail="User not found")
        users.append(user_by_id)

    if user_email:
        user_by_email = await users_collection.find_one({"username_email": user_email})
        if user_by_email is None:
            raise HTTPException(status_code=404, detail="User not found")
        users.append(user_by_email)

    if keycloak_sub:
        user_by_keycloak_sub = await users_collection.find_one({"keycloak_sub": keycloak_sub})
        if user_by_keycloak_sub is None:
            raise HTTPException(status_code=404, detail="User not found")
        users.append(user_by_keycloak_sub)

    if not users:
        raise HTTPException(
            status_code=400,
            detail="One of user_id, username_email, or keycloak_sub is required",
        )

    first_user = users[0]
    for user in users[1:]:
        if user["_id"] != first_user["_id"]:
            raise HTTPException(
                status_code=400,
                detail="Provided identifiers refer to different users",
            )

    return first_user


def _ensure_keycloak_config() -> None:
    if not KEYCLOAK_BASE_URL or not KEYCLOAK_REALM:
        raise HTTPException(status_code=500, detail="Keycloak registration is not configured")
    if not KEYCLOAK_ADMIN_USERNAME or not KEYCLOAK_ADMIN_PASSWORD:
        raise HTTPException(status_code=500, detail="Keycloak admin credentials are not configured")


async def _get_keycloak_admin_token() -> str:
    _ensure_keycloak_config()
    token_url = f"{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_ADMIN_REALM}/protocol/openid-connect/token"
    payload = {
        "client_id": KEYCLOAK_ADMIN_CLIENT_ID,
        "grant_type": "password",
        "username": KEYCLOAK_ADMIN_USERNAME,
        "password": KEYCLOAK_ADMIN_PASSWORD,
    }
    if KEYCLOAK_ADMIN_CLIENT_SECRET:
        payload["client_secret"] = KEYCLOAK_ADMIN_CLIENT_SECRET

    async with httpx.AsyncClient(timeout=15.0) as client_http:
        response = await client_http.post(token_url, data=payload)

    if response.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Unable to obtain Keycloak admin token: {response.text}")

    access_token = response.json().get("access_token")
    if not access_token:
        raise HTTPException(status_code=502, detail="Keycloak admin token response did not include access_token")
    return access_token


async def _find_keycloak_user_by_email(email: str, admin_token: str) -> Optional[dict[str, Any]]:
    users_url = f"{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM}/users"
    headers = {"Authorization": f"Bearer {admin_token}"}
    params = {"email": email}

    async with httpx.AsyncClient(timeout=15.0) as client_http:
        response = await client_http.get(users_url, headers=headers, params=params)

    if response.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Unable to search Keycloak users: {response.text}")

    email_lower = email.lower()
    for item in response.json():
        if str(item.get("email", "")).lower() == email_lower:
            return item
    return None


async def _find_keycloak_user_by_username(username: str, admin_token: str) -> Optional[dict[str, Any]]:
    users_url = f"{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM}/users"
    headers = {"Authorization": f"Bearer {admin_token}"}
    params = {"username": username, "exact": "true"}

    async with httpx.AsyncClient(timeout=15.0) as client_http:
        response = await client_http.get(users_url, headers=headers, params=params)

    if response.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Keycloak username lookup failed: {response.text}")

    username_lower = username.lower()
    for item in response.json():
        if str(item.get("username", "")).lower() == username_lower:
            return item
    return None


async def _create_keycloak_user(user: User, raw_password: str, admin_token: str) -> str:

    # creates the Keycloak account first.
    # If Keycloak creation succeeds,
    # it returns the Keycloak user id, stored as keycloak_sub.

    existing_keycloak_user = await _find_keycloak_user_by_email(str(user.username_email), admin_token)
    if existing_keycloak_user is not None:
        raise HTTPException(status_code=400, detail="Email already registered in Keycloak")

    existing_keycloak_username = await _find_keycloak_user_by_username(str(user.username), admin_token)
    if existing_keycloak_username is not None:
        raise HTTPException(status_code=400, detail="Username already registered in Keycloak")

    users_url = f"{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM}/users"
    headers = {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json",
    }

    payload = {
        "username": str(user.username),
        "email": str(user.username_email),
        "enabled": True,
        "emailVerified": True,
        "firstName": user.first_name,
        "lastName": user.last_name,
        "attributes": {
            "user_type": _keycloak_attr_list(user.type),
            "organization": _keycloak_attr_list(normalize_org(user.organization)),
            "incorporation": _keycloak_attr_list(user.incorporation),
            "address": _keycloak_attr_list(user.address),
            "VAT_No": _keycloak_attr_list(user.vat_no),
            "positionTitle": _keycloak_attr_list(user.position_title),
            "phone": _keycloak_attr_list(user.phone),
        },
        "credentials": [
            {
                "type": "password",
                "value": raw_password,
                "temporary": False,
            }
        ],
    }


    # create the Keycloak identity first so MongoDB can store the returned
    # Keycloak subject and keep both systems linked from the start.
    async with httpx.AsyncClient(timeout=20.0) as client_http:
        response = await client_http.post(users_url, headers=headers, json=payload)

    if response.status_code not in (201, 204):
        if response.status_code == 409:
            raise HTTPException(status_code=400, detail="User already registered in Keycloak")
        raise HTTPException(status_code=502, detail=f"Failed to create Keycloak user: {response.text}")

    location = response.headers.get("Location", "")
    keycloak_sub = location.rstrip("/").split("/")[-1] if location else ""
    if keycloak_sub:
        return keycloak_sub

    created_user = await _find_keycloak_user_by_email(str(user.username_email), admin_token)
    if not created_user or not created_user.get("id"):
        raise HTTPException(status_code=502, detail="Keycloak user was created but could not be resolved afterwards")
    return str(created_user["id"])


async def _delete_keycloak_user(keycloak_sub: str, admin_token: str) -> None:
    if not keycloak_sub:
        return
    delete_url = f"{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM}/users/{keycloak_sub}"
    headers = {"Authorization": f"Bearer {admin_token}"}
    async with httpx.AsyncClient(timeout=15.0) as client_http:
        response = await client_http.delete(delete_url, headers=headers)
    if response.status_code not in (204, 404):
        logger.warning("Failed to delete Keycloak user %s during rollback: %s", keycloak_sub, response.text)


async def _update_keycloak_password(keycloak_sub: str, raw_password: str, admin_token: str) -> None:
    reset_url = f"{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM}/users/{keycloak_sub}/reset-password"
    headers = {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json",
    }
    payload = {"type": "password", "value": raw_password, "temporary": False}
    async with httpx.AsyncClient(timeout=15.0) as client_http:
        response = await client_http.put(reset_url, headers=headers, json=payload)
    if response.status_code != 204:
        raise HTTPException(status_code=502, detail=f"Failed to update Keycloak password: {response.text}")


async def _update_keycloak_user(
    keycloak_sub: str,
    updates: dict[str, Any],
    admin_token: str,
) -> None:
    update_url = f"{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM}/users/{keycloak_sub}"
    headers = {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json",
    }

    payload = {
        "username": updates.get("username"),
        "email": updates.get("username_email"),
        "firstName": updates.get("first_name"),
        "lastName": updates.get("last_name"),
        "attributes": {
            "user_type": _keycloak_attr_list(updates.get("type")),
            "organization": _keycloak_attr_list(updates.get("organization")),
            "incorporation": _keycloak_attr_list(updates.get("incorporation")),
            "address": _keycloak_attr_list(updates.get("address")),
            "VAT_No": _keycloak_attr_list(updates.get("vat_no")),
            "positionTitle": _keycloak_attr_list(updates.get("position_title")),
            "phone": _keycloak_attr_list(updates.get("phone")),
        },
    }

    async with httpx.AsyncClient(timeout=15.0) as client_http:
        response = await client_http.put(update_url, headers=headers, json=payload)

    if response.status_code != 204:
        raise HTTPException(status_code=502, detail=f"Failed to update Keycloak user: {response.text}")


async def _resolve_keycloak_sub_for_user(existing_user: dict[str, Any], admin_token: str) -> Optional[str]:
    keycloak_sub = existing_user.get("keycloak_sub")
    if keycloak_sub:
        return str(keycloak_sub)

    email = existing_user.get("username_email")
    if not email:
        return None

    keycloak_user = await _find_keycloak_user_by_email(str(email), admin_token)
    if keycloak_user and keycloak_user.get("id"):
        keycloak_sub = str(keycloak_user["id"])
        await users_collection.update_one(
            {"_id": existing_user["_id"]},
            {"$set": {"keycloak_sub": keycloak_sub}},
        )
        existing_user["keycloak_sub"] = keycloak_sub
        return keycloak_sub
    return None


async def _delete_keycloak_user_for_local_user(existing_user: dict[str, Any], admin_token: str) -> None:
    keycloak_sub = await _resolve_keycloak_sub_for_user(existing_user, admin_token)
    if keycloak_sub:
        await _delete_keycloak_user(keycloak_sub, admin_token)


async def is_strong_password(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, "Password is strong."


async def verify_master(master_password_input: str) -> bool:
    admin_user = await users_collection.find_one({"is_admin": True})

    if admin_user is not None:
        master_password = admin_user.get("password")
    else:
        raw_master_password = os.getenv("MASTER_PASSWORD")
        if not raw_master_password:
            raise HTTPException(
                status_code=500, detail="MASTER_PASSWORD environment variable not set"
            )

        master_password = get_password_hash(raw_master_password)
        first_admin = {
            "username_email": "admin@example.com",
            "password": master_password,
            "is_admin": True,
        }
        await users_collection.insert_one(first_admin)

    if not verify_password(master_password_input, master_password):
        raise HTTPException(status_code=403, detail="Invalid master password")

    return True


def _claims_has_admin_role(claims: dict[str, Any]) -> bool:
    role_values = []
    realm_access = claims.get("realm_access") or {}
    role_values.extend(str(role).lower() for role in (realm_access.get("roles") or []))
    resource_access = claims.get("resource_access") or {}
    for client_access in resource_access.values():
        role_values.extend(str(role).lower() for role in ((client_access or {}).get("roles") or []))
    return "admin" in role_values

def _build_keycloak_token_url() -> str:
    keycloak_issuer = (os.getenv("KEYCLOAK_ISSUER") or "").rstrip("/")
    if not keycloak_issuer:
        raise HTTPException(status_code=500, detail="KEYCLOAK_ISSUER environment variable not set")
    return f"{keycloak_issuer}/protocol/openid-connect/token"


async def verify_access_token_and_resolve_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        if not KEYCLOAK_ISSUER or not KEYCLOAK_JWKS_URL:
            raise HTTPException(status_code=503, detail="Keycloak authentication is not configured")
        payload = decode_keycloak_token(
            token,
            issuer=KEYCLOAK_ISSUER,
            jwks_url=KEYCLOAK_JWKS_URL,
            audience=KEYCLOAK_AUDIENCE or None,
            verify_aud=bool(KEYCLOAK_AUDIENCE),
            logger=logger,
        )
        email: Optional[str] = payload.get("email")
        sub: Optional[str] = payload.get("sub")
        if email is None or sub is None:
            raise credentials_exception
    except HTTPException:
        raise
    except Exception:
        raise credentials_exception

    user = await resolve_or_create_local_user_async(
        users_collection,
        payload,
        logger,
        include_audit_fields=False,
    )

    return {
        "claims": payload,
        "user": user,
        "is_admin": _claims_has_admin_role(payload),
    }


async def resolve_optional_access_token(token: Optional[str] = Depends(oauth2_scheme_optional)):
    if not token:
        return None
    return await verify_access_token_and_resolve_user(token)


def _principal_user(current_principal: dict[str, Any]) -> dict[str, Any]:
    return current_principal["user"]


def _principal_user_id(current_principal: dict[str, Any]) -> str:
    user = _principal_user(current_principal)
    return str(user["_id"])


def _require_admin(current_principal: dict[str, Any]) -> None:
    if not current_principal.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin role required")


def _authorize_self_or_admin(current_principal: dict[str, Any], target_user: dict[str, Any]) -> None:
    if current_principal.get("is_admin"):
        return

    if str(target_user["_id"]) != _principal_user_id(current_principal):
        raise HTTPException(status_code=403, detail="Not authorized for this user")


def _authorize_self_only(current_principal: dict[str, Any], target_user: dict[str, Any]) -> None:
    if str(target_user["_id"]) != _principal_user_id(current_principal):
        raise HTTPException(status_code=403, detail="Not authorized for this user")


@app.post("/user/login/", summary="Login via Keycloak")
async def login_user_via_authentication_service(form_data: OAuth2PasswordRequestForm = Depends()):

    # call ../protocol/openid-connect/token" request an access token
    client_id = KEYCLOAK_CLIENT_ID or "user-management-api"
    token_url = _build_keycloak_token_url()
    form_payload = {
        "client_id": client_id,
        "grant_type": form_data.grant_type or "password",
        "username": form_data.username,
        "password": form_data.password,
    }
    requested_scopes = [scope for scope in (form_data.scopes or []) if scope]
    for required_scope in ("openid", "profile", "email"):
        if required_scope not in requested_scopes:
            requested_scopes.append(required_scope)
    form_payload["scope"] = " ".join(requested_scopes)
    if KEYCLOAK_CLIENT_SECRET:
        form_payload["client_secret"] = KEYCLOAK_CLIENT_SECRET

    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(token_url, data=form_payload)

    if response.status_code >= 400:
        try:
            payload = response.json()
        except Exception:
            payload = {"detail": response.text or "Keycloak login failed"}

        detail = (
            payload.get("error_description")
            or payload.get("detail")
            or payload.get("error")
            or "Keycloak login failed"
        )
        raise HTTPException(status_code=response.status_code, detail=detail)
    print("response.json():", response.json())
    return response.json()


@app.post("/user/register", response_model=User)
async def register_user(user: User, master_password_input: str):
    # await verify_master(master_password_input)

    """
        1. Validate input locally.
        2. Create Keycloak user first, using Admin privilege.
        3. Store returned Keycloak id as keycloak_sub in Mongo.
        4. Insert Mongo profile.
        5. If Mongo fails, delete the just-created Keycloak user.
    """


    # validating the master password with verify_master(...).
    # then checks MongoDB for duplicates on username_email, and also checks that username is present and not already
    # used locally.Password strength is validated with is_strong_password(...).
    if await users_collection.find_one({"username_email": user.username_email}):
        raise HTTPException(status_code=400, detail="Email already registered")

    if not user.username:
        raise HTTPException(status_code=400, detail="Username is required")

    if user.username and await users_collection.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username already registered")

    if not user.password:
        raise HTTPException(status_code=400, detail="Password is required")

    is_strong, resp = await is_strong_password(user.password)
    if not is_strong:
        raise HTTPException(
            status_code=400,
            detail=resp or "Password does not meet strength requirements",
        )


    raw_password = user.password

    # get token using Admin user!
    admin_token = await _get_keycloak_admin_token()
    # create a user in the Keycloak, get the keycloak-id
    keycloak_sub = await _create_keycloak_user(user, raw_password, admin_token)

    user_dict = None
    try:
        user.organization = normalize_org(user.organization)
        user.keycloak_sub = keycloak_sub
        user.password = get_password_hash(raw_password)
        user_dict = user.model_dump(by_alias=True, exclude_unset=True)
        # after getting keycloak-id, the user is inserted into MongoDB
        result = await users_collection.insert_one(user_dict)
        user_dict["_id"] = str(result.inserted_id)
        user_dict["password"] = None
    except Exception as exc:
        # if inset into MongoDB fails
        # rolls the Keycloak userback using _delete_keycloak_user
        # That prevents ending up with a Keycloak user that has no matching Mongo profile.

        await _delete_keycloak_user(keycloak_sub, admin_token)
        raise HTTPException(
            status_code=400,
            detail="User cannot be created (possible reason, duplicate user ID)",
        ) from exc

    if not user_dict:
        raise HTTPException(status_code=500, detail="User registration failed unexpectedly")
    return user_dict


@app.put("/user/update-password", response_model=User)
async def update_user_password(
    master_password_input: Optional[str] = None,
    user_update: UserUpdatePassword = None,
    current_principal: Optional[dict[str, Any]] = Depends(resolve_optional_access_token),
):

    """
    Request Body, example:
    {
        "user_id": "<mongo_id>",
        "username_email": "user@example.com",
        "keycloak_sub": "<keycloak_id>",
        "password": "NewStrongPass1!"
    }

    """

    if user_update is None:
        raise HTTPException(status_code=400, detail="Password update payload is required")

    existing_user = await _find_user_for_password_update(
        user_id=user_update.user_id,
        user_email=str(user_update.username_email) if user_update.username_email else None,
        keycloak_sub=user_update.keycloak_sub,
    )

    if current_principal is not None:
        _authorize_self_only(current_principal, existing_user)
    else:
        if not master_password_input:
            raise HTTPException(status_code=401, detail="Authentication is required")
        # await verify_master(master_password_input)

    if not user_update.password:
        raise HTTPException(status_code=400, detail="Password is required")

    is_strong, resp = await is_strong_password(user_update.password)
    if not is_strong:
        raise HTTPException(
            status_code=400,
            detail=resp or "Password does not meet strength requirements",
        )

    if KEYCLOAK_BASE_URL and KEYCLOAK_REALM and KEYCLOAK_ADMIN_USERNAME and KEYCLOAK_ADMIN_PASSWORD:
        admin_token = await _get_keycloak_admin_token()
        keycloak_sub = await _resolve_keycloak_sub_for_user(existing_user, admin_token)
        if keycloak_sub:
            await _update_keycloak_password(keycloak_sub, user_update.password, admin_token)

    updated_password_hash = get_password_hash(user_update.password)
    update_result = await users_collection.update_one(
        {"_id": existing_user["_id"]}, {"$set": {"password": updated_password_hash}}
    )

    if update_result.modified_count == 0:
        raise HTTPException(status_code=500, detail="Failed to update password")

    updated_user = await users_collection.find_one({"_id": existing_user["_id"]})
    return _mask_password(updated_user)


@app.put("/user/update-details", response_model=User)
async def update_user_details(
    user_update: UserDetailsUpdate,
    user_id: Optional[str] = Query(None, description="ID of the user to update"),
    user_email: Optional[EmailStr] = Query(None, description="Email of the user to update"),
    current_principal: dict[str, Any] = Depends(verify_access_token_and_resolve_user),

):

    """
    Request body example:

    {
      "first_name": "Consumer5",
      "last_name": "Datapack",
      "name": "Consumer5 Datapack",
      "username": "datapack_consumer5",
      "type": "consumer",
      "username_email": "datapack_consumer5@example.com",

      "organization": [
        "SOTON"
      ],
      "incorporation": "University",
      "address": "Jhon Roan",
      "vat_no": "1234567890",
      "position_title": "Head of Data",
      "phone": "000000000000"
    }
    """

    existing_user = await _find_user(user_id=user_id, user_email=str(user_email) if user_email else None)
    _authorize_self_only(current_principal, existing_user)

    update_fields = user_update.model_dump(exclude_unset=True)
    if "password" in update_fields:
        raise HTTPException(status_code=400, detail="Password cannot be updated via /user/update-details")

    if not update_fields:
        return _mask_password(existing_user)

    if "username_email" in update_fields:
        new_email = str(update_fields["username_email"])
        if new_email != existing_user.get("username_email"):
            duplicate_user = await users_collection.find_one({"username_email": new_email})
            if duplicate_user and duplicate_user["_id"] != existing_user["_id"]:
                raise HTTPException(status_code=400, detail="Email already registered")
            update_fields["username_email"] = new_email

    if "username" in update_fields:
        new_username = _clean_optional_string(update_fields["username"])
        if new_username and new_username != existing_user.get("username"):
            duplicate_user = await users_collection.find_one({"username": new_username})
            if duplicate_user and duplicate_user["_id"] != existing_user["_id"]:
                raise HTTPException(status_code=400, detail="Username already registered")
        update_fields["username"] = new_username

    if "organization" in update_fields:
        update_fields["organization"] = normalize_org(update_fields["organization"])

    first_name_provided = "first_name" in update_fields
    last_name_provided = "last_name" in update_fields
    name_provided = "name" in update_fields
    if first_name_provided or last_name_provided or name_provided:
        if name_provided and not first_name_provided and not last_name_provided:
            name_value = _clean_optional_string(update_fields.get("name"))
            if name_value:
                parts = name_value.split(None, 1)
                update_fields["first_name"] = parts[0]
                update_fields["last_name"] = parts[1] if len(parts) > 1 else None
                update_fields["name"] = name_value
            else:
                update_fields["first_name"] = None
                update_fields["last_name"] = None
                update_fields["name"] = None
        else:
            merged_first_name = _clean_optional_string(
                update_fields.get("first_name", existing_user.get("first_name"))
            )
            merged_last_name = _clean_optional_string(
                update_fields.get("last_name", existing_user.get("last_name"))
            )
            update_fields["first_name"] = merged_first_name
            update_fields["last_name"] = merged_last_name
            update_fields["name"] = _compose_name(merged_first_name, merged_last_name)

    keycloak_sync_fields = {
        "username",
        "username_email",
        "first_name",
        "last_name",
        "type",
        "organization",
        "incorporation",
        "address",
        "vat_no",
        "position_title",
        "phone",
    }
    if KEYCLOAK_BASE_URL and KEYCLOAK_REALM and any(field in update_fields for field in keycloak_sync_fields):
        admin_token = await _get_keycloak_admin_token()
        keycloak_sub = await _resolve_keycloak_sub_for_user(existing_user, admin_token)

        if keycloak_sub:
            new_username = update_fields.get("username")
            if new_username:
                existing_keycloak_user = await _find_keycloak_user_by_username(str(new_username), admin_token)
                if existing_keycloak_user and str(existing_keycloak_user.get("id")) != str(keycloak_sub):
                    raise HTTPException(status_code=400, detail="Username already registered in Keycloak")

            new_email = update_fields.get("username_email")
            if new_email:
                existing_keycloak_user = await _find_keycloak_user_by_email(str(new_email), admin_token)
                if existing_keycloak_user and str(existing_keycloak_user.get("id")) != str(keycloak_sub):
                    raise HTTPException(status_code=400, detail="Email already registered in Keycloak")

            keycloak_updates = {
                "username": update_fields.get("username", existing_user.get("username")),
                "username_email": update_fields.get("username_email", existing_user.get("username_email")),
                "first_name": update_fields.get("first_name", existing_user.get("first_name")),
                "last_name": update_fields.get("last_name", existing_user.get("last_name")),
                "type": update_fields.get("type", existing_user.get("type")),
                "organization": update_fields.get("organization", existing_user.get("organization")),
                "incorporation": update_fields.get("incorporation", existing_user.get("incorporation")),
                "address": update_fields.get("address", existing_user.get("address")),
                "vat_no": update_fields.get("vat_no", existing_user.get("vat_no")),
                "position_title": update_fields.get("position_title", existing_user.get("position_title")),
                "phone": update_fields.get("phone", existing_user.get("phone")),
            }
            await _update_keycloak_user(keycloak_sub, keycloak_updates, admin_token)

    update_result = await users_collection.update_one(
        {"_id": existing_user["_id"]},
        {"$set": update_fields},
    )

    if update_result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")

    updated_user = await users_collection.find_one({"_id": existing_user["_id"]})
    return _mask_password(updated_user)


@app.get("/user/details/", response_model=User, summary="Get details of a user")
async def get_user_details(
    user_id: Optional[str] = Query(None, description="ID of the user to fetch"),
    user_email: Optional[EmailStr] = Query(None, description="Email of the user to fetch"),
    keycloak_sub: Optional[str] = Query(None, description="Keycloak user id to fetch"),
    current_principal: dict[str, Any] = Depends(verify_access_token_and_resolve_user),

):
    try:
        user = await _find_user(
            user_id=user_id,
            user_email=str(user_email) if user_email else None,
            keycloak_sub=keycloak_sub,
        )
        _authorize_self_or_admin(current_principal, user)
        return _mask_password(user)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"Failed to retrieve user details: {str(exc)}"
        ) from exc


@app.get("/user/list/", response_model=list[User], summary="List users")
async def list_users(
    current_principal: dict[str, Any] = Depends(verify_access_token_and_resolve_user),
):
    try:
        _require_admin(current_principal)
        users = []
        cursor = users_collection.find().sort("username_email", 1)
        async for user in cursor:
            users.append(_mask_password(user))
        return users
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"Failed to retrieve users: {str(exc)}"
        ) from exc


def _check_valid_email(email):
    email = (email or "").strip()
    if not email:
        return False, "Email is required."

    if email.count("@") != 1:
        return False, "Email must contain exactly one '@' symbol."

    local_part, domain_part = email.split("@", 1)

    if not local_part:
        return False, "Email must include text before '@'."

    if not domain_part:
        return False, "Email must include a domain after '@'."

    if "." not in domain_part:
        return False, "Email domain must include a '.' and a valid suffix."

    domain_name, _, tld = domain_part.rpartition(".")
    if not domain_name:
        return False, "Email domain name is missing before the final '.'."

    if len(tld) < 2:
        return False, "Email domain suffix must contain at least 2 letters."

    EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", re.I)
    valid = EMAIL_PATTERN.fullmatch(email) is not None
    if not valid:
        return False, "Email contains invalid characters or format."

    return True, "Email is valid."

@app.get("/user/check_user_email/")
async def check_user_email(
    user_email: EmailStr = Query(..., description="Email address to check"),
):
    # check if it is a valid email
    is_valid, megs = _check_valid_email(user_email)
    if not is_valid:
        return {"user_email": str(user_email), "flag": False, "detail": {megs}}

    # check if it is an existing user
    user = await users_collection.find_one(
        {"username_email": str(user_email)},
        {"_id": 1},
    )

    if user:

        return {"user_email": str(user_email), "flag": True, "detail":"Email already registered."}

    else:
        return {"user_email": str(user_email), "flag": False, "detail":"Email can be used."}


@app.get("/user/check_username/")
async def check_username(
    username: str = Query(..., min_length=1, description="Username to check"),
):
    username = username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")

    user = await users_collection.find_one(
        {"username": username},
        {"_id": 1},
    )

    if user:
        return {"username": username, "flag": True, "detail": "Username already registered."}

    return {"username": username, "flag": False, "detail": "Username can be used."}



@app.delete("/user/delete/{user_id}")
async def delete_user(
    user_id: str,
    current_principal: dict[str, Any] = Depends(verify_access_token_and_resolve_user),
):
    _require_admin(current_principal)
    try:
        object_id = ObjectId(user_id)
    except InvalidId as exc:
        raise HTTPException(status_code=400, detail="Invalid user id") from exc

    existing_user = await users_collection.find_one({"_id": object_id})
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")

    admin_token = await _get_keycloak_admin_token()
    await _delete_keycloak_user_for_local_user(existing_user, admin_token)

    delete_result = await users_collection.delete_one({"_id": object_id})
    if delete_result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User deleted successfully"}




@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8800")))
