from rest_framework.decorators import api_view
from rest_framework.response import Response


@api_view(["GET"])
def getRoutes(request):
    routes = [
        {"url": "/api/list/", "method": "GET"},
        {"url": "/api/token/", "method": "POST"},
        {"url": "/api/token/refresh/", "method": "POST"},
        {"url": "/api/register/", "method": "POST"},
        {"url": "/api/register/verify_email/", "method": "POST"},
        {"url": "/api/register/resend_otp/", "method": "POST"},
        {"url": "/api/users/", "method": "GET"},
        {"url": "/api/users/{id}", "method": "GET"},
        {"url": "/api/users/{id}", "method": "PATCH"},
        {"url": "/api/users/{id}", "method": "DELETE"},
    ]

    return Response(routes)
