from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
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
        return super(UserSerializer, self).create(validated_data)

    class Meta:
        model = User
        fields = ["username", "email", "password", "bio", "profile_picture"]
