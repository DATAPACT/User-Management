
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


logger = logging.getLogger(__name__)

API_BASE_URL = os.getenv("USER_MANAGEMENT_API_URL", "http://localhost:8800")


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

def check_user_email(user_email: str) :
    endpoint_url = f"{API_BASE_URL}/user/check_user_email/"

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


def check_username(username: str):
    endpoint_url = f"{API_BASE_URL}/user/check_username/"

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


# def login_view(request):
#   if request.method == "POST":
#     messages.info(request, "Login handling is not implemented yet in the Django frontend.")
#   return render(request, "login.html")


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
            return render(request, "sign-up.html", {"form_data": form_data})

        if not last_name:
            messages.error(request, "Last name cannot be empty.")
            return render(request, "sign-up.html", {"form_data": form_data})

        if not username:
            messages.error(request, "Username cannot be empty.")
            return render(request, "sign-up.html", {"form_data": form_data})

        if password != confirm_password:
            messages.error(request, "The confirmation password does not match.")
            return render(request, "sign-up.html", {"form_data": form_data})

        email_exists = check_user_email(email)
        if email_exists is True:
            messages.error(request, "Email already registered, please use another email.")
            return render(request, "sign-up.html", {"form_data": form_data})

        username_exists = check_username(username)
        if username_exists is True:
            messages.error(request, "Username already registered, please use another username.")
            return render(request, "sign-up.html", {"form_data": form_data})


        # user registration is handled by user-management-service. Keycloak is
        # the authentication authority, while profile creation lives in the
        # dedicated user-management service.

        endpoint_url = f"{API_BASE_URL}/user/register/"

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
                return render(request, "sign-up.html", {"form_data": form_data})

        except requests.RequestException:
            messages.error(request, "Registration service is unavailable. Please try again later.")
            return render(request, "sign-up.html", {"form_data": form_data})

    return render(request, "sign-up.html")




def manage_account_view(request):
  return render(request, "manage_account.html")


def check_user_email_view(request):
  user_email = (request.GET.get("email") or request.GET.get("user_email") or "").strip()
  if not user_email:
    return JsonResponse({"detail": "Email is required"}, status=400)

  try:
    data = check_user_email(user_email)
    return JsonResponse(data)
  except Exception as exc:
    return JsonResponse({"detail": str(exc)}, status=502)


def check_username_view(request):
  username = (request.GET.get("username") or "").strip()
  if not username:
    return JsonResponse({"detail": "Username is required"}, status=400)

  try:
    data = check_username(username)
    return JsonResponse(data)
  except Exception as exc:
    return JsonResponse({"detail": str(exc)}, status=502)



def login(request):
    if request.method == "POST":
        identifier = (
            request.POST.get("identifier")
            or request.POST.get("username")
            or request.POST.get("email")
        )
        password = request.POST.get("password")

        print("\n\nidentifier (username or email: )", identifier)
        print("\n\npassword: ", password)

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

            # login is delegated to Keycloak. Negotiation-Tool stores the
            # Keycloak access token directly instead of asking negotiation-api
            # to mint an internal JWT.
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
                print(user)
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
            return redirect("manage_account")
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
