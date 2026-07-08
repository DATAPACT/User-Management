
import os
import difflib
import html
import json
import logging
import os
import re
import threading
import httpx
from django.contrib import messages
from django.http import JsonResponse
from django.shortcuts import render
from . import settings
from django.shortcuts import redirect
from django.shortcuts import render
from typing import List, Dict, Optional, Any
import requests
from keycloak_auth.auth import decode_keycloak_token
from keycloak_auth.user_mapping import resolve_local_session_user_sync
from pymongo import MongoClient as PyMongoClient
import phonenumbers

import time
from functools import wraps
from django.shortcuts import redirect
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)

API_USER_MANAGEMENT_BASE_URL = os.getenv("USER_MANAGEMENT_API_URL", "http://localhost:8800")


_mongo_client = None
_mongo_lock = threading.Lock()
MONGO_DB = os.environ.get("MONGO_DB", "dips_services")


def _get_mongo_users():
    global _mongo_client
    if _mongo_client is None:
        with _mongo_lock:
            if _mongo_client is None:
                mongo_user = os.environ.get("MONGO_USER", "root")
                mongo_password = os.environ.get("MONGO_PASSWORD")
                mongo_host = os.environ.get("MONGO_HOST", "mongo")
                mongo_port = os.environ.get("MONGO_PORT", "27017")
                uri = f"mongodb://{mongo_user}:{mongo_password}@{mongo_host}:{mongo_port}"
                _mongo_client = PyMongoClient(uri)

    user_info = _mongo_client[MONGO_DB]["users"]
    print("user_info", user_info)

    return user_info

def _build_keycloak_url(path: str) -> str:
    issuer = settings.KEYCLOAK_ISSUER.rstrip("/")
    return f"{issuer}{path}"


def _decode_keycloak_claims(token: str) -> Dict[str, Any]:
    keycloak_issuer = settings.KEYCLOAK_ISSUER
    if not keycloak_issuer:
        raise ValueError("KEYCLOAK_ISSUER is not configured")
    return decode_keycloak_token(
        token,
        issuer=keycloak_issuer.rstrip("/"),
        jwks_url=f"{keycloak_issuer.rstrip('/')}/protocol/openid-connect/certs",
        verify_aud=False,
        logger=logger,
    )


def _resolve_local_session_user_from_claims(claims: Dict[str, Any]) -> Dict[str, Any]:
    return resolve_local_session_user_sync(_get_mongo_users(), claims, logger)


def _email_exists_response_value(data):
    if not isinstance(data, dict):
        return None

    for key in ["flag", "exists", "email_exists", "user_exists", "is_existing", "is_registered", "registered"]:
        if key in data:
            return bool(data[key])

def _check_user_email_exists(user_email: str) :
    endpoint_url = f"{API_USER_MANAGEMENT_BASE_URL}/user/check_user_email/"

    try:

        response = requests.get(endpoint_url, params={"user_email": user_email}, timeout=10)
        if response.status_code == 404:
            return False
        response.raise_for_status()
        exists = _email_exists_response_value(response.json())
        if exists is not None:
            return exists
    except (requests.RequestException, ValueError) as exc:
        logger.warning("Email availability check failed: %s", exc)

    return None


def _check_username_exists(username: str):
    endpoint_url = f"{API_USER_MANAGEMENT_BASE_URL}/user/check_username/"

    try:
        response = requests.get(endpoint_url, params={"username": username}, timeout=10)
        if response.status_code == 404:
            return False
        response.raise_for_status()
        exists = _email_exists_response_value(response.json())
        if exists is not None:
            return exists
    except (requests.RequestException, ValueError) as exc:
        logger.warning("Username availability check failed: %s", exc)

    return None


def _get_logged_in_user_id(request) -> Optional[str]:
    user_id = request.session.get("user_id")
    return str(user_id) if user_id else None


def _get_access_token(request) -> Optional[str]:
    token = request.session.get("access_token")
    return str(token) if token else None


def _auth_headers(request) -> Dict[str, str]:
    token = _get_access_token(request)
    if not token:
        raise ValueError("Missing access token in session")
    return {"Authorization": f"Bearer {token}"}


def _get_user_details(request, user_id: Optional[str] = None, **extra_params: str) -> Any:
    endpoint_url = f"{API_USER_MANAGEMENT_BASE_URL}/user/details/"
    params: Dict[str, str] = {}
    if user_id:
        params["user_id"] = user_id
    for key, value in extra_params.items():
        if isinstance(value, str) and value.strip():
            params[key] = value.strip()
    response = requests.get(endpoint_url, params=params, headers=_auth_headers(request), timeout=10)
    response.raise_for_status()
    return response.json()


def _update_user_details(request, user_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    endpoint_url = f"{API_USER_MANAGEMENT_BASE_URL}/user/update-details"
    response = requests.put(
        endpoint_url,
        params={"user_id": user_id},
        json=payload,
        headers=_auth_headers(request),
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def _update_user_password(request, payload: Dict[str, Any]) -> Dict[str, Any]:
    endpoint_url = f"{API_USER_MANAGEMENT_BASE_URL}/user/update-password"
    headers = None
    params = None
    token = _get_access_token(request)
    if token:
        headers = {"Authorization": f"Bearer {token}"}
    else:
        master_password = os.getenv("MASTER_PASSWORD", "master_password")
        params = {"master_password_input": master_password}

    response = requests.put(endpoint_url, params=params, json=payload, headers=headers, timeout=15)
    response.raise_for_status()
    return response.json()


def _list_users(request) -> list[Dict[str, Any]]:
    endpoint_url = f"{API_USER_MANAGEMENT_BASE_URL}/user/list/"
    response = requests.get(endpoint_url, headers=_auth_headers(request), timeout=15)
    response.raise_for_status()
    return response.json()


def _delete_user(request, user_id: str) -> Dict[str, Any]:
    endpoint_url = f"{API_USER_MANAGEMENT_BASE_URL}/user/delete/{user_id}"
    response = requests.delete(endpoint_url, headers=_auth_headers(request), timeout=15)
    response.raise_for_status()
    return response.json()


def _claims_has_admin_role(claims: Dict[str, Any]) -> bool:
    role_values = []
    realm_access = claims.get("realm_access") or {}
    role_values.extend(str(role).lower() for role in (realm_access.get("roles") or []))
    resource_access = claims.get("resource_access") or {}
    for client_access in resource_access.values():
        role_values.extend(str(role).lower() for role in ((client_access or {}).get("roles") or []))
    return "admin" in role_values


def _is_admin_session(request) -> bool:
    return bool(request.session.get("is_admin"))


def is_strong_password(password: str) -> tuple[bool, str]:
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

def index_view(request):
  return render(request, "index.html")



REGISTRATION_FORM_FIELDS = [
    "first_name",
    "last_name",
    "email",
    "username",
    "user_type",
    "organization",
    "incorporation",
    "address",
    "vat_no",
    "position_title",
    "phone_region",
    "phone",
]


def _registration_form_data(post_data):
    return {
        field: (post_data.get(field) or "").strip()
        for field in REGISTRATION_FORM_FIELDS
    }

def _build_full_name(first_name: Optional[str], last_name: Optional[str]) -> Optional[str]:
    parts = [part.strip() for part in [first_name or "", last_name or ""] if part and part.strip()]
    return " ".join(parts) or None


PHONE_REGION_CACHE = None
# add more regions if needed
COMMON_PHONE_REGIONS = [
    {"name": "United States", "region_code": "US", "dial_code": "+1"},
    {"name": "United Kingdom", "region_code": "GB", "dial_code": "+44"},
    {"name": "Canada", "region_code": "CA", "dial_code": "+1"},
    {"name": "Germany", "region_code": "DE", "dial_code": "+49"},
    {"name": "France", "region_code": "FR", "dial_code": "+33"},
    {"name": "Spain", "region_code": "ES", "dial_code": "+34"},
    {"name": "Italy", "region_code": "IT", "dial_code": "+39"},
    {"name": "Netherlands", "region_code": "NL", "dial_code": "+31"},
    {"name": "Sweden", "region_code": "SE", "dial_code": "+46"},
    {"name": "Switzerland", "region_code": "CH", "dial_code": "+41"},
    {"name": "Norway", "region_code": "NO", "dial_code": "+47"},
    {"name": "Denmark", "region_code": "DK", "dial_code": "+45"},
    {"name": "Ireland", "region_code": "IE", "dial_code": "+353"},
    {"name": "Portugal", "region_code": "PT", "dial_code": "+351"},
    {"name": "Poland", "region_code": "PL", "dial_code": "+48"},
    {"name": "Mexico", "region_code": "MX", "dial_code": "+52"},
    {"name": "Brazil", "region_code": "BR", "dial_code": "+55"},
    {"name": "Argentina", "region_code": "AR", "dial_code": "+54"},
    {"name": "Australia", "region_code": "AU", "dial_code": "+61"},
    {"name": "New Zealand", "region_code": "NZ", "dial_code": "+64"},
    {"name": "Japan", "region_code": "JP", "dial_code": "+81"},
    {"name": "China", "region_code": "CN", "dial_code": "+86"},
    {"name": "Hong Kong", "region_code": "HK", "dial_code": "+852"},
    {"name": "Singapore", "region_code": "SG", "dial_code": "+65"},
    {"name": "India", "region_code": "IN", "dial_code": "+91"},
    {"name": "Pakistan", "region_code": "PK", "dial_code": "+92"},
    {"name": "Iran", "region_code": "IR", "dial_code": "+98"},
    {"name": "Saudi Arabia", "region_code": "SA", "dial_code": "+966"},
    {"name": "United Arab Emirates", "region_code": "AE", "dial_code": "+971"},
    {"name": "South Africa", "region_code": "ZA", "dial_code": "+27"},
]
PHONE_REGION_NAME_TO_CODE = {
    entry["name"].casefold(): entry["region_code"]
    for entry in COMMON_PHONE_REGIONS
}





def _load_phone_region_choices():
    global PHONE_REGION_CACHE
    if PHONE_REGION_CACHE is not None:
        return PHONE_REGION_CACHE

    PHONE_REGION_CACHE = [
        (entry["name"], f'{entry["name"]} ({entry["dial_code"]})')
        for entry in COMMON_PHONE_REGIONS
    ]
    return PHONE_REGION_CACHE


def _registration_page_context(form_data=None):
    return {
        "form_data": form_data or {},
        "phone_region_choices": _load_phone_region_choices(),
    }


def _check_valid_phone(phone: str, phone_region: str) -> tuple[bool, str, Optional[str]]:

    # use the exising phonenumbers package
    phone = (phone or "").strip()
    phone_region = (phone_region or "").strip()

    if not phone:
        return True, "", None

    if not phone_region:
        return False, "Please choose a phone region.", None

    region_code = PHONE_REGION_NAME_TO_CODE.get(phone_region.casefold())
    if not region_code:
        return False, "Phone region is not recognised.", None

    try:
        parsed = phonenumbers.parse(phone, region_code)
    except phonenumbers.NumberParseException:
        return False, "Phone number format is invalid for the selected region.", None

    if not phonenumbers.is_possible_number(parsed):
        return False, "Phone number is not possible for the selected region.", None

    if not phonenumbers.is_valid_number(parsed):
        return False, "Phone number is not valid for the selected region.", None

    normalized_phone = phonenumbers.format_number(
        parsed,
        phonenumbers.PhoneNumberFormat.E164,
    )
    return True, "Phone number is valid.", normalized_phone


def _infer_phone_region_name(phone: str) -> str:
    phone = (phone or "").strip()
    if not phone:
        return ""

    try:
        parsed = phonenumbers.parse(phone, None)
    except phonenumbers.NumberParseException:
        return ""

    region_code = phonenumbers.region_code_for_number(parsed)
    if not region_code:
        return ""

    for entry in COMMON_PHONE_REGIONS:
        if entry["region_code"] == region_code:
            return entry["name"]
    return ""




MANAGE_ACCOUNT_FORM_FIELDS = [
    "first_name",
    "last_name",
    "username",
    "username_email",
    "type",
    "organization",
    "incorporation",
    "address",
    "vat_no",
    "position_title",
    "phone_region",
    "phone",
]


def _manage_account_form_data(post_data):
    return {
        field: (post_data.get(field) or "").strip()
        for field in MANAGE_ACCOUNT_FORM_FIELDS
    }


def _to_form_string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(item).strip() for item in value if str(item).strip())
    return str(value).strip()


def _build_manage_account_context(user_details: Dict[str, Any], form_data=None):
    active_form_data = form_data or {
        "user_id": _to_form_string(user_details.get("_id") or user_details.get("id")),
        "first_name": _to_form_string(user_details.get("first_name")),
        "last_name": _to_form_string(user_details.get("last_name")),
        "username": _to_form_string(user_details.get("username")),
        "username_email": _to_form_string(user_details.get("username_email")),
        "type": _to_form_string(user_details.get("type")),
        "organization": _to_form_string(user_details.get("organization")),
        "incorporation": _to_form_string(user_details.get("incorporation")),
        "address": _to_form_string(user_details.get("address")),
        "vat_no": _to_form_string(user_details.get("vat_no")),
        "position_title": _to_form_string(user_details.get("position_title")),
        "phone_region": _infer_phone_region_name(_to_form_string(user_details.get("phone"))),
        "phone": _to_form_string(user_details.get("phone")),
    }
    active_form_data.setdefault(
        "user_id",
        _to_form_string(user_details.get("_id") or user_details.get("id")),
    )
    welcome_name = (
        _to_form_string(user_details.get("name"))
        or _build_full_name(user_details.get("first_name"), user_details.get("last_name"))
        or _to_form_string(user_details.get("username"))
        or "User"
    )
    return {
        "welcome_name": welcome_name,
        "form_data": active_form_data,
        "is_sso": True,
        "phone_region_choices": _load_phone_region_choices(),
        "read_only_mode": False,
        "is_admin_view": False,
        "sidebar_active": "profile",
    }


def _search_form_data(data) -> Dict[str, str]:
    return {
        "username": (data.get("username") or "").strip(),
        "user_email": (data.get("user_email") or "").strip(),
        "organization": (data.get("organization") or "").strip(),
    }





def admin_delete_user(request, user_id: str):
    if request.method != "POST":
        return redirect("admin_manage")

    if not _is_admin_session(request):
        messages.error(request, "Admin access is required.")
        return redirect("login")

    session_user_id = _get_logged_in_user_id(request)
    if str(user_id) == str(session_user_id):
        messages.error(request, "You cannot delete the currently logged-in admin user.")
        return redirect("admin_manage")

    try:
        _delete_user(request, user_id)
        messages.success(request, "User deleted successfully.")
    except requests.HTTPError as exc:
        try:
            detail = exc.response.json().get("detail", "Could not delete the user.")
        except ValueError:
            detail = "Could not delete the user."
        messages.error(request, detail)
    except requests.RequestException:
        messages.error(request, "Delete service is unavailable.")

    return redirect("admin_manage")


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

def check_user_email(request):
    if request.method != "GET":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    email = (request.GET.get("email") or "").strip()
    if not email:
        return JsonResponse({"error": "Missing email"}, status=400)


    is_valid, megs = _check_valid_email(email)
    if not is_valid:
        return JsonResponse(
            {"valid": False, "detail": megs},
            status=400,
        )

    exists = _check_user_email_exists(email)
    if exists is None:
        return JsonResponse(
            {"error": "Email availability service is unavailable."},
            status=503,
        )

    return JsonResponse({"exists": exists})


def check_username(request):
    if request.method != "GET":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    username = (request.GET.get("username") or "").strip()
    if not username:
        return JsonResponse({"error": "Missing username"}, status=400)

    exists = _check_username_exists(username)
    if exists is None:
        return JsonResponse(
            {"error": "Username availability service is unavailable."},
            status=503,
        )

    return JsonResponse({"exists": exists})

def check_strong_password(request):
    if request.method != "GET":
        return JsonResponse({"error": "Method not allowed"}, status=405)
    password = (request.GET.get("password") or "").strip()

    if not password:
        return JsonResponse({"error": "Missing password"}, status=400)

    is_strong, megs  = is_strong_password(password)

    if not is_strong:
        return JsonResponse({"valid": False, "detail": megs})

    return JsonResponse({"valid": True, "detail": megs})


def check_phone_number(request):
    if request.method != "GET":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    # get phone number and region
    phone = (request.GET.get("phone") or "").strip()
    phone_region = (request.GET.get("phone_region") or "").strip()

    if not phone:
        return JsonResponse({"valid": True, "detail": ""})

    # verify the phone number
    is_valid, detail, normalized_phone = _check_valid_phone(phone, phone_region)
    if not is_valid:
        return JsonResponse({"valid": False, "detail": detail}, status=400)

    return JsonResponse({"valid": True, "detail": detail, "normalized_phone": normalized_phone})

def manage_account(request):
    session_user_id = _get_logged_in_user_id(request)
    if not session_user_id:
        messages.error(request, "Please log in first.")
        return redirect("login")

    requested_user_id = (request.GET.get("user_id") or "").strip()
    is_admin = _is_admin_session(request)
    target_user_id = requested_user_id or session_user_id

    try:
        user_details = _get_user_details(request, target_user_id)

    except (requests.RequestException, ValueError):
        messages.error(request, "Could not load your account details right now.")
        return redirect("admin_manage" if is_admin else "login")

    def render_manage_account(current_user_details, current_form_data=None, *, read_only=False):
        context = _build_manage_account_context(current_user_details, current_form_data)
        context["read_only_mode"] = read_only
        context["is_admin_view"] = is_admin
        context["sidebar_active"] = "profile"
        return render(request, "manage-account.html", context)

    read_only_mode = bool(is_admin or target_user_id != session_user_id)

    if request.method == "POST":
        if read_only_mode:
            messages.error(request, "This profile view is read-only.")
            return render_manage_account(user_details, read_only=read_only_mode)

        form_data = _manage_account_form_data(request.POST)

        if not form_data["first_name"]:
            messages.error(request, "First name cannot be empty.")
            return render_manage_account(user_details, form_data)

        if not form_data["last_name"]:
            messages.error(request, "Last name cannot be empty.")
            return render_manage_account(user_details, form_data)

        if not form_data["username"]:
            messages.error(request, "Username cannot be empty.")
            return render_manage_account(user_details, form_data)

        if not form_data["username_email"]:
            messages.error(request, "Email cannot be empty.")
            return render_manage_account(user_details, form_data)

        is_valid_email, email_message = _check_valid_email(form_data["username_email"])
        if not is_valid_email:
            messages.error(request, email_message)
            return render_manage_account(user_details, form_data)

        if form_data["username"] != _to_form_string(user_details.get("username")):
            username_exists = _check_username_exists(form_data["username"])

            if username_exists is True:
                messages.error(request, "Username already registered, please use another username.")
                return render_manage_account(user_details, form_data)

        if form_data["username_email"] != _to_form_string(user_details.get("username_email")):
            email_exists = _check_user_email_exists(form_data["username_email"])

            if email_exists is True:
                messages.error(request, "Email already registered, please use another email.")
                return render_manage_account(user_details, form_data)

        phone_is_valid, phone_message, normalized_phone = _check_valid_phone(
            form_data["phone"],
            form_data["phone_region"],
        )
        if not phone_is_valid:
            messages.error(request, phone_message)
            return render_manage_account(user_details, form_data)

        payload = {
            "first_name": form_data["first_name"],
            "last_name": form_data["last_name"],
            "username": form_data["username"],
            "username_email": form_data["username_email"],
            "type": form_data["type"] or _to_form_string(user_details.get("type")),
            "organization": form_data["organization"],
            "incorporation": form_data["incorporation"],
            "address": form_data["address"],
            "vat_no": form_data["vat_no"],
            "position_title": form_data["position_title"],
            "phone": normalized_phone or "",
        }

        try:
            updated_user = _update_user_details(request, session_user_id, payload)
        except requests.HTTPError as exc:
            try:
                detail = exc.response.json().get("detail", "Could not update your profile.")
            except ValueError:
                detail = "Could not update your profile."
            messages.error(request, detail)
            return render_manage_account(user_details, form_data)
        except (requests.RequestException, ValueError):
            messages.error(request, "Profile update service is unavailable.")
            return render_manage_account(user_details, form_data)

        messages.success(request, "Profile updated successfully.")
        return render_manage_account(updated_user)

    return render_manage_account(user_details, read_only=read_only_mode)


def search_user(request):
    session_user_id = _get_logged_in_user_id(request)
    if not session_user_id:
        messages.error(request, "Please log in first.")
        return redirect("login")

    form_data = {"username": "", "user_email": "", "organization": ""}
    users = []

    if request.method == "GET":
        form_data = _search_form_data(request.GET)
        if any(form_data.values()):
            try:
                search_result = _get_user_details(request, **form_data)
                if isinstance(search_result, list):
                    users = search_result
                elif isinstance(search_result, dict) and search_result:
                    users = [search_result]
                else:
                    users = []
            except requests.HTTPError as exc:
                try:
                    detail = exc.response.json().get("detail", "Could not search users right now.")
                except ValueError:
                    detail = "Could not search users right now."
                messages.error(request, detail)
            except (requests.RequestException, ValueError):
                messages.error(request, "Search service is unavailable right now.")

    normalized_users = []
    for user in users:
        normalized_user = dict(user)
        normalized_user["user_id"] = str(user.get("_id") or user.get("id") or "")
        normalized_user["organization_text"] = _to_form_string(user.get("organization"))
        normalized_users.append(normalized_user)

    return render(
        request,
        "search-user.html",
        {
            "is_sso": True,
            "is_admin_view": _is_admin_session(request),
            "sidebar_active": "search",
            "form_data": form_data,
            "users": normalized_users,
            "has_searched": any(form_data.values()),
        },
    )


def admin_search_user(request):
    if not _is_admin_session(request):
        messages.error(request, "Admin access is required.")
        return redirect("login")

    form_data = {"username": "", "user_email": "", "organization": ""}
    users = []

    if request.method == "GET":
        form_data = _search_form_data(request.GET)
        if any(form_data.values()):
            try:
                search_result = _get_user_details(request, **form_data)
                if isinstance(search_result, list):
                    users = search_result
                elif isinstance(search_result, dict) and search_result:
                    users = [search_result]
                else:
                    users = []
            except requests.HTTPError as exc:
                try:
                    detail = exc.response.json().get("detail", "Could not search users right now.")
                except ValueError:
                    detail = "Could not search users right now."
                messages.error(request, detail)
            except (requests.RequestException, ValueError):
                messages.error(request, "Search service is unavailable right now.")

    normalized_users = []
    for user in users:
        normalized_user = dict(user)
        normalized_user["user_id"] = str(user.get("_id") or user.get("id") or "")
        normalized_user["organization_text"] = _to_form_string(user.get("organization"))
        normalized_user["is_current_admin"] = normalized_user["user_id"] == str(_get_logged_in_user_id(request))
        normalized_users.append(normalized_user)

    return render(
        request,
        "search-user.html",
        {
            "is_sso": True,
            "is_admin_view": True,
            "sidebar_active": "search",
            "form_data": form_data,
            "users": normalized_users,
            "has_searched": any(form_data.values()),
            "is_admin_search_view": True,
        },
    )


def admin_manage(request):
    if not _is_admin_session(request):
        messages.error(request, "Admin access is required.")
        return redirect("login")

    session_user_id = _get_logged_in_user_id(request)
    admin_user_name = "Admin"
    if session_user_id:
        try:
            admin_user = _get_user_details(request, session_user_id)
            admin_user_name = (
                _to_form_string(admin_user.get("name"))
                or _build_full_name(admin_user.get("first_name"), admin_user.get("last_name"))
                or _to_form_string(admin_user.get("username"))
                or "Admin"
            )
        except (requests.RequestException, ValueError):
            admin_user_name = "Admin"

    try:
        users = _list_users(request)
    except (requests.RequestException, ValueError):
        messages.error(request, "Could not load the user list right now.")
        return render(
            request,
            "admin-manage.html",
            {"is_sso": True, "is_admin_view": True, "users": [], "admin_user_name": admin_user_name},
        )

    normalized_users = []
    for user in users:
        user_id = str(user.get("_id") or user.get("id") or "")
        normalized_user = dict(user)
        normalized_user["user_id"] = user_id
        normalized_user["is_current_admin"] = user_id == str(session_user_id)
        normalized_users.append(normalized_user)

    return render(
        request,
        "admin-manage.html",
        {
            "is_sso": True,
            "is_admin_view": True,
            "users": normalized_users,
            "admin_user_name": admin_user_name,
            "sidebar_active": "list",
        },
    )

def reset_password_view(request):
    user_id = _get_logged_in_user_id(request)
    is_logged_in = bool(user_id)
    form_data = {
        "email": "",
    }
    current_user = None
    reset_success = False

    if is_logged_in:
        try:
            current_user = _get_user_details(request, user_id)
        except (requests.RequestException, ValueError):
            messages.error(request, "Could not load your account details right now.")
            return redirect("manage_account")

    if request.method == "POST":
        email = (request.POST.get("email") or "").strip()
        password = request.POST.get("password") or ""
        confirm_password = request.POST.get("confirmpassword") or ""
        form_data["email"] = email

        if not is_logged_in:
            if not email:
                messages.error(request, "Email is required.")
                return render(
                    request,
                    "reset-password.html",
                    {"is_sso": is_logged_in, "form_data": form_data, "current_user": current_user, "reset_success": reset_success},
                )
            is_valid_email, email_message = _check_valid_email(email)
            if not is_valid_email:
                messages.error(request, email_message)
                return render(
                    request,
                    "reset-password.html",
                    {"is_sso": is_logged_in, "form_data": form_data, "current_user": current_user, "reset_success": reset_success},
                )

        if not password:
            messages.error(request, "New password is required.")
            return render(
                request,
                "reset-password.html",
                {"is_sso": is_logged_in, "form_data": form_data, "current_user": current_user, "reset_success": reset_success},
            )

        if password != confirm_password:
            messages.error(request, "The confirmation password does not match.")
            return render(
                request,
                "reset-password.html",
                {"is_sso": is_logged_in, "form_data": form_data, "current_user": current_user, "reset_success": reset_success},
            )

        is_strong, message = is_strong_password(password)
        if not is_strong:
            messages.error(request, message)
            return render(
                request,
                "reset-password.html",
                {"is_sso": is_logged_in, "form_data": form_data, "current_user": current_user, "reset_success": reset_success},
            )

        payload = {"password": password}
        if is_logged_in:
            payload["user_id"] = user_id
        else:
            payload["username_email"] = email

        try:
            _update_user_password(request, payload)
        except requests.HTTPError as exc:
            try:
                detail = exc.response.json().get("detail", "Could not reset your password.")
            except ValueError:
                detail = "Could not reset your password."
            messages.error(request, detail)
            return render(
                request,
                "reset-password.html",
                {"is_sso": is_logged_in, "form_data": form_data, "current_user": current_user, "reset_success": reset_success},
            )
        except (requests.RequestException, ValueError):
            messages.error(request, "Password reset service is unavailable.")
            return render(
                request,
                "reset-password.html",
                {"is_sso": is_logged_in, "form_data": form_data, "current_user": current_user, "reset_success": reset_success},
            )

        request.session.flush()
        reset_success = True
        return render(
            request,
            "reset-password.html",
            {"is_sso": False, "form_data": {"email": ""}, "current_user": None, "reset_success": reset_success},
        )

    return render(
        request,
        "reset-password.html",
        {"is_sso": is_logged_in, "form_data": form_data, "current_user": current_user, "reset_success": reset_success},
    )

def register(request):
    if request.method == "POST":
        print("Registering user...")
        form_data = _registration_form_data(request.POST)
        first_name = form_data["first_name"]
        last_name = form_data["last_name"]
        user_name = _build_full_name(first_name, last_name)
        email = form_data["email"]
        username = form_data["username"]
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirmpassword")
        user_type = form_data["user_type"]  # Default to 'consumer' if not provided
        organization = form_data["organization"]
        # distinctive_title = request.POST.get("distinctive_title")
        incorporation = form_data["incorporation"]
        address = form_data["address"]
        vat_no = form_data["vat_no"]
        position_title = form_data["position_title"]
        phone_region = form_data["phone_region"]
        phone = form_data["phone"]

        data = {
            "first_name": first_name,
            "last_name": last_name,
            "name": user_name,
            "username": username,
            "type": user_type,
            "username_email": email,
            "password": password,
            "organization": organization,
            "incorporation": incorporation,
            "address": address,
            "vat_no": vat_no,
            "position_title": position_title,
            "phone": phone,
        }

        master_password = os.getenv("MASTER_PASSWORD", "master_password")

        if not first_name:
            messages.error(request, "First name cannot be empty.")
            return render(request, "sign-up.html", _registration_page_context(form_data))

        if not last_name:
            messages.error(request, "Last name cannot be empty.")
            return render(request, "sign-up.html", _registration_page_context(form_data))

        if not username:
            messages.error(request, "Username cannot be empty.")
            return render(request, "sign-up.html", _registration_page_context(form_data))

        if password != confirm_password:
            messages.error(request, "The confirmation password does not match.")
            return render(request, "sign-up.html", _registration_page_context(form_data))

        email_exists = _check_user_email_exists(email)
        if email_exists is True:
            messages.error(request, "Email already registered, please use another email.")
            return render(request, "sign-up.html", _registration_page_context(form_data))

        username_exists = _check_username_exists(username)
        if username_exists is True:
            messages.error(request, "Username already registered, please use another username.")
            return render(request, "sign-up.html", _registration_page_context(form_data))

        is_strong, message = is_strong_password(password)

        if not is_strong:
            messages.error(request, message)
            return render(request, "sign-up.html", _registration_page_context(form_data))

        phone_is_valid, phone_message, normalized_phone = _check_valid_phone(phone, phone_region)
        if not phone_is_valid:
            messages.error(request, phone_message)
            return render(request, "sign-up.html", _registration_page_context(form_data))
        data["phone"] = normalized_phone or ""

        # user registration is handled by user-management-service. Keycloak is the authentication authority
        endpoint_url = f"{API_USER_MANAGEMENT_BASE_URL}/user/register/"

        try:
            response = requests.post(f"{endpoint_url}?master_password_input={master_password}",
                                     json=data)
            if response.status_code in [200, 201]:
                response_data = response.json()
                print(f"User registered successfully: {response_data}")
                messages.success(request, "Account created successfully! Please log in.")
                return redirect("login")
            else:
                # Handle errors returned from FastAPI
                try:
                    error_message = response.json().get("detail", "Registration failed.")
                except ValueError:
                    error_message = "Unexpected response from the registration service."

                messages.error(request, error_message)
                return render(request, "sign-up.html", _registration_page_context(form_data))

        except requests.RequestException:
            messages.error(request, "Registration service is unavailable. Please try again later.")
            return render(request, "sign-up.html", _registration_page_context(form_data))

    return render(request, "sign-up.html", _registration_page_context())

def login(request):
    if request.method == "POST":
        identifier = (
            request.POST.get("identifier")
            or request.POST.get("username")
            or request.POST.get("email")
        )
        password = request.POST.get("password")

        print("\n\nidentifier (username or email: )", identifier)
        print("password: ", password)

        if not identifier or not password:
            messages.error(request, "Please enter both username/email and password.")
            return redirect("login")

        if not settings.KEYCLOAK_ISSUER or not settings.KEYCLOAK_CLIENT_ID:
            messages.error(request, "Keycloak login is not configured.")
            return redirect("login")

        try:
            token_url = _build_keycloak_url("/protocol/openid-connect/token")
            data = {
                "client_id": settings.KEYCLOAK_CLIENT_ID,
                "grant_type": "password",
                "scope": "openid profile email",
                # Keycloak's token endpoint expects the credential identifier in
                # the `username` field. That identifier can be the real Keycloak
                # username and may also be an email depending on realm config.
                "username": identifier,
                "password": password,
            }
            if settings.KEYCLOAK_CLIENT_SECRET:
                data["client_secret"] = settings.KEYCLOAK_CLIENT_SECRET

            # login is delegated to Keycloak.
            response = requests.post(token_url, data=data, timeout=10)
            print(f"Response status code: {response.status_code}")
            print(f"Response content: {response.content}")
        except requests.RequestException as e:
            messages.error(request, "Login service is unavailable. Please try again later.")
            return redirect("login")

        if response.status_code == 200:
            resp_data = response.json()
            access_token = resp_data.get("access_token")
            if not access_token:
                messages.error(request, "Keycloak did not return an access token.")
                return redirect("login")

            try:
                claims = _decode_keycloak_claims(access_token)
                user = _resolve_local_session_user_from_claims(claims)
                is_admin = _claims_has_admin_role(claims)
                print("\n\nis_admin: ",is_admin)
                print("print out current user info: ", user)
            except Exception as exc:
                logger.error("Keycloak login succeeded but local user resolution failed: %s", exc)
                messages.error(request, "Login succeeded, but the user is not authorized.")
                return redirect("login")

            # Save token and user info in session
            try:
                # Rotate session to avoid stale cached baselines across logins
                request.session.cycle_key()
            except Exception:
                pass
            request.session["access_token"] = access_token
            request.session["refresh_token"] = resp_data.get("refresh_token")
            request.session["user_id"] = user.get("id")
            request.session["user_type"] = user.get("type")
            request.session["is_sso"] = False
            request.session["is_admin"] = is_admin
            request.session["claims"] = claims
            return redirect("admin_manage" if is_admin else "manage_account")
        else:
            # Extract API error message if any, or default message
            try:
                body = response.json()
                detail = body.get("error_description") or body.get("detail") or body.get("error") or "Invalid username or password."
            except Exception:
                detail = "Invalid username or password."

            messages.error(request, detail)
            return redirect("login")

    # For GET requests, just render login page
    return render(request, "login.html")


@csrf_exempt  # Keycloak JWT validation provides the request authenticity here.
def sso_login(request):
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        body = json.loads(request.body)
        token = body.get("token")
        if not token:
            return JsonResponse({"error": "Missing token"}, status=400)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    if not settings.KEYCLOAK_ISSUER:
        return JsonResponse({"error": "SSO not configured"}, status=503)

    try:
        claims = _decode_keycloak_claims(token)
        user = _resolve_local_session_user_from_claims(claims)
        is_admin = _claims_has_admin_role(claims)
    except Exception as exc:
        logger.error("[SSO] Local user resolution failed: %s", exc)
        return JsonResponse({"error": "User is not authorized in User-Management"}, status=401)

    request.session["access_token"] = token
    request.session["user_id"] = user.get("id")
    request.session["user_type"] = user.get("type")
    request.session["is_sso"] = True
    request.session["is_admin"] = is_admin
    request.session["claims"] = claims

    redirect_name = "admin_manage" if is_admin else "manage_account"
    return JsonResponse({"status": "ok", "redirect_url": redirect(redirect_name).url})

def logout_view(request):
    request.session.flush()
    return redirect("login")


def keycloak_login_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        access_token = request.session.get("access_token")
        claims = request.session.get("claims")

        if not access_token or not claims:
            return redirect("login")

        exp = claims.get("exp")
        if not exp or exp < int(time.time()):
            request.session.flush()
            return redirect("login")

        return view_func(request, *args, **kwargs)

    return wrapper
