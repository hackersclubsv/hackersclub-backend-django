from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import Comment, CustomUser, Group, Post, Tag


class CustomUserAdmin(UserAdmin):
    list_display = ("username", "id", "email", "role")
    readonly_fields = ("id",)
    fieldsets = (
        ("User Info", {"fields": ("id", "username", "password")}),
        (
            ("Personal info"),
            {
                "fields": (
                    "first_name",
                    "last_name",
                    "email",
                    "is_verified",
                    "bio",
                    "profile_picture",
                    "role",
                )
            },
        ),
        (("Important dates"), {"fields": ("last_login", "date_joined")}),
        (
            ("Permissions"),
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                )
            },
        ),
    )


admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Tag)
admin.site.register(Post)
admin.site.register(Comment)
admin.site.register(Group)
