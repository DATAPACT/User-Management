
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



def check_user_email(user_email: str) -> dict:
  with httpx.Client(timeout=10.0) as client:
    response = client.get(
      f"{API_BASE_URL}/user/check_user_email/",
      params={"user_email": user_email},
    )
    response.raise_for_status()
    data = response.json()
  return {
    "user_email": data.get("user_email", user_email),
    "exists": bool(data.get("flag", False)),
    "detail": data.get("detail", ""),
  }


def check_username(username: str) -> dict:
  with httpx.Client(timeout=10.0) as client:
    response = client.get(
      f"{API_BASE_URL}/user/check_username/",
      params={"username": username},
    )
    response.raise_for_status()
    data = response.json()
  return {
    "username": data.get("username", username),
    "exists": bool(data.get("flag", False)),
    "detail": data.get("detail", ""),
  }


# def login_view(request):
#   if request.method == "POST":
#     messages.info(request, "Login handling is not implemented yet in the Django frontend.")
#   return render(request, "login.html")


def index_view(request):
  return render(request, "index.html")


def sign_up_view(request):
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
