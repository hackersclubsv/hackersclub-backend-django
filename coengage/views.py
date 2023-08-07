import os
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.files.storage import default_storage
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import permissions, status, viewsets
from rest_framework.exceptions import NotFound
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from .serializers import (
    ChangePasswordSerializer,
    PasswordResetSerializer,
    RegisterSerializer,
    RequestPasswordResetSerializer,
    ResendOTPSerializer,
    UserSerializer,
    VerifyEmailSerializer,
)
from .utilities import generate_otp, send_email_ses

User = get_user_model()


class IsOwnerOrReadOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return obj == request.user


class IsOwnerOrAdmin(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj == request.user or request.user.role == User.ADMIN


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    # lookup_field = 'email'
    permission_classes = [IsOwnerOrReadOnly]
    authentication_classes = [JWTAuthentication]
    http_method_names = ["get", "patch", "head", "options", "delete"]

    def get_permissions(self):
        if getattr(self, "swagger_fake_view", False):
            # VIEW USED FOR SCHEMA GENERATION PURPOSES
            return []
        if self.action == "destroy":
            self.permission_classes = [IsOwnerOrAdmin]
        return super(UserViewSet, self).get_permissions()

    def create(self, request, *args, **kwargs):
        raise NotFound("This method is not available.")

    @transaction.atomic
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        if "profile_picture" in request.FILES:
            self.handle_profile_picture_upload(request, instance)
        return Response(serializer.data)

    def handle_profile_picture_upload(self, request, instance):
        file = request.FILES["profile_picture"]

        # Determine the S3 file name
        _, file_extension = os.path.splitext(file.name)
        s3_file_name = f"users/{instance.id}/profile_picture{file_extension}"

        # Save the file to S3
        default_storage.save(s3_file_name, file)

        # Update the URL of the profile picture
        instance.profile_picture = default_storage.url(s3_file_name)

        instance.save()

    @transaction.atomic
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(
            {"status": "User successfully deleted."}, status=status.HTTP_204_NO_CONTENT
        )


class RegisterView(CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [permissions.AllowAny]
    serializer_class = RegisterSerializer

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        try:
            user = User.objects.get(email=request.data["email"])
        except User.DoesNotExist:
            return Response(
                {"error": "User could not be created."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        email_response = send_email_ses(user.username, user.otp, user.email)

        if not email_response["success"]:
            return Response(
                {"email_error": "OTP not sent", "message": email_response["message"]},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(
            {"status": "Registration successful. Please verify your email."},
            status=status.HTTP_201_CREATED,
        )


class VerifyEmail(APIView):
    serializer_class = VerifyEmailSerializer

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        otp = serializer.validated_data["otp"]

        user = get_object_or_404(User, email=email)

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
                status=status.HTTP_400_BAD_REQUEST,
            )

        elif otp == user.otp:
            user.is_verified = True
            user.otp = None
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
    serializer_class = ResendOTPSerializer

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        user = get_object_or_404(User, email=email)

        if user.is_verified:
            return Response(
                {"status": "Email already verified, please Login"},
                status=status.HTTP_200_OK,
            )
        user.otp = generate_otp()
        user.otp_created_at = timezone.now()
        user.otp_expiration = timezone.now() + timedelta(minutes=10)
        user.save()

        email_response = send_email_ses(user.username, user.otp, user.email)
        if not email_response["success"]:
            return Response(
                {"email_error": "OTP not sent", "message": email_response["message"]},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(
            {"status": "New OTP sent, please check your email."},
            status=status.HTTP_200_OK,
        )


class RequestPasswordReset(APIView):
    serializer_class = RequestPasswordResetSerializer

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        user = get_object_or_404(User, email=email)

        user.otp = generate_otp()
        user.otp_created_at = timezone.now()
        user.otp_expiration = timezone.now() + timedelta(minutes=10)
        user.save()

        email_response = send_email_ses(user.username, user.otp, user.email)
        if not email_response["success"]:
            return Response(
                {"email_error": "OTP not sent", "message": email_response["message"]},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(
            {"status": "OTP sent, please check your email."},
            status=status.HTTP_200_OK,
        )


class PasswordReset(APIView):
    serializer_class = PasswordResetSerializer

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        otp = serializer.validated_data["otp"]
        email = serializer.validated_data["email"]
        new_password = serializer.validated_data["password"]
        user = get_object_or_404(User, email=email)

        # Check if OTP has expired
        if (
            otp is not None
            and user.otp is not None
            and timezone.now() > user.otp_expiration
        ):
            return Response(
                {"status": "OTP has expired"}, status=status.HTTP_400_BAD_REQUEST
            )

        if otp == user.otp:
            user.set_password(new_password)
            user.otp = None
            user.otp_expiration = None
            user.save()

            return Response(
                {"status": "Password successfully reset."},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"status": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST
            )


class ChangePasswordView(APIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    @transaction.atomic
    def patch(self, request, *args, **kwargs):
        user = request.user
        print(user.email)
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        # Check old password
        if not user.check_password(serializer.validated_data.get("old_password")):
            return Response(
                {"status": "Wrong old password."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.set_password(serializer.validated_data.get("new_password"))
        user.save()

        return Response(
            {"status": "Password updated successfully"}, status=status.HTTP_200_OK
        )
