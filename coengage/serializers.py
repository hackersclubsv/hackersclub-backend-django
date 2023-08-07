from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .utilities import generate_otp

User = get_user_model()


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        token["username"] = user.username
        token["email"] = user.email

        return token

    def validate(self, attrs):
        data = super().validate(attrs)

        if not self.user.is_verified:
            raise serializers.ValidationError("Email is not verified")

        return data


class URLImageField(serializers.ImageField):
    def to_representation(self, value):
        return value


class UserSerializer(serializers.ModelSerializer):
    profile_picture = URLImageField(use_url=True, required=False)
    email = serializers.EmailField(read_only=True, required=True)

    def validate_email(self, value):
        value = value.strip().lower()
        if not value.endswith("@northeastern.edu"):
            raise serializers.ValidationError(
                "Email must be from the northeastern.edu domain"
            )
        return value

    class Meta:
        model = User
        fields = ["username", "email", "bio", "profile_picture"]


class RegisterSerializer(UserSerializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)

    class Meta(UserSerializer.Meta):
        fields = ["username", "email", "password"]

    def create(self, validated_data):
        validated_data["password"] = make_password(validated_data.get("password"))
        validated_data["otp"] = generate_otp()
        validated_data["otp_created_at"] = timezone.now()
        validated_data["otp_expiration"] = timezone.now() + timedelta(minutes=10)
        validated_data["otp_attempts"] = 0
        validated_data["otp_attempts_timestamp"] = None
        return super().create(validated_data)


class ResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)


class VerifyEmailSerializer(serializers.Serializer):
    otp = serializers.IntegerField(required=True)
    email = serializers.EmailField(required=True)


class RequestPasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)


class PasswordResetSerializer(serializers.Serializer):
    otp = serializers.IntegerField(required=True)
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True)


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
