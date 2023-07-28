import random

from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.utils import timezone
from rest_framework import permissions, status, viewsets
from rest_framework.generics import CreateAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from .models import CustomUser
from .serializers import UserSerializer

User = get_user_model()


def SendEmail(username, otp, email):
    send_mail(
        subject="Your one-time password",
        message="",
        html_message=f"""
                            <p>Hello {username},</p>
                            <p>You requested a one-time password. Use this password to continue your process.</p>
                            <table width='100%'><tr><td style='text-align: center; font-size: 28px; font-weight: bold;'>{otp}</td></tr></table>
                            <p>If you didn't request this email, please ignore it.</p>
                            <p>-- Northeastern University Silicon Valley HackersClub</p>
                          """,
        from_email="vidyalathanataraja.r@northeastern.edu",
        recipient_list=[email],
        fail_silently=False,
    )


class UserViewSet(viewsets.ModelViewSet):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer

    def get_permissions(self):
        if self.action == "create":
            # Allow any user (authenticated or not) to access this action
            return [permissions.AllowAny()]
        return [permissions.IsAuthenticated()]


class RegisterView(CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [permissions.AllowAny]
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        user = User.objects.get(email=request.data["email"])
        refresh = RefreshToken.for_user(user)
        SendEmail(user.username, user.otp, user.email)

        return Response(
            {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                **response.data,
            }
        )


class VerifyEmail(APIView):
    def post(self, request, *args, **kwargs):
        otp = request.data.get("otp")
        email = request.data.get("email")
        user = CustomUser.objects.get(email=email)

        # Check if OTP has expired
        if timezone.now() > user.otp_expiration:
            return Response(
                {"status": "OTP has expired"}, status=status.HTTP_400_BAD_REQUEST
            )

        # Check if OTP verification is blocked due to too many attempts
        if (
            user.otp_attempts >= 3
            and (timezone.now() - user.otp_attempts_timestamp).total_seconds() < 600
        ):
            return Response(
                {"status": "Too many failed attempts. Please try again later."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if user.is_verified:
            return Response(
                {"status": "Email already verified, please Login"},
                status=status.HTTP_200_OK,
            )
        elif otp == user.otp:
            user.is_verified = True
            user.otp_attempts = 0
            user.otp_attempts_timestamp = None
            user.save()
            return Response(
                {"status": "Email verified, please proceed to Login page"},
                status=status.HTTP_200_OK,
            )
        else:
            user.otp_attempts += 1
            if user.otp_attempts == 1:
                user.otp_attempts_timestamp = timezone.now()
            user.save()
            return Response(
                {"status": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST
            )


class ResendOTP(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        user = CustomUser.objects.get(email=email)

        if user.is_verified:
            return Response(
                {"status": "Email already verified, please Login"},
                status=status.HTTP_200_OK,
            )
        user.otp = str(random.randint(100000, 999999))
        user.otp_created_at = timezone.now()
        user.save()

        SendEmail(user.username, user.otp, user.email)

        return Response(
            {"status": "New OTP sent, please check your email."},
            status=status.HTTP_200_OK,
        )
