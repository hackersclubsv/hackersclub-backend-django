import random
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

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


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    def validate_email(self, value):
        if not value.endswith("@northeastern.edu"):
            raise serializers.ValidationError(
                "Email must be from the northeastern.edu domain"
            )
        return value

    def create(self, validated_data):
        validated_data["password"] = make_password(validated_data.get("password"))
        validated_data["otp"] = str(random.randint(100000, 999999))
        validated_data["otp_created_at"] = timezone.now()
        validated_data["otp_expiration"] = timezone.now() + timedelta(minutes=10)
        validated_data["otp_attempts"] = 0
        validated_data["otp_attempts_timestamp"] = None
        return super(UserSerializer, self).create(validated_data)

    class Meta:
        model = User
        fields = ["username", "email", "password", "bio", "profile_picture"]
