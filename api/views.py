from rest_framework.decorators import api_view
from rest_framework.response import Response


@api_view(["GET"])
def getRoutes(request):
    routes = [
        "/api/token/",
        "/api/token/refresh/",
        "/api/register/",
        "/api/register/verify_email/",
        "/api/register/resend_otp/",
    ]

    return Response(routes)
