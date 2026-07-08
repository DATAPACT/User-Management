import json

from django.conf import settings


def sso_config(request):
    return {
        "APP_BASE_PATH": settings.APP_BASE_PATH,
        "SSO_TRUSTED_ORIGINS_JSON": json.dumps(getattr(settings, "FRAME_ANCESTORS", [])),
    }
