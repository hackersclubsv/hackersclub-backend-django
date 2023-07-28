from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import RegisterView, ResendOTP, UserViewSet, VerifyEmail

router = DefaultRouter()
router.register(r"users", UserViewSet)

urlpatterns = [
    path("", include(router.urls)),
    path("register/", RegisterView.as_view(), name="register"),
    path("register/verify_email/", VerifyEmail.as_view(), name="verify-email"),
    path("register/resend_otp/", ResendOTP.as_view(), name="resend-otp"),
]
