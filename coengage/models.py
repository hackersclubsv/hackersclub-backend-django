from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class CustomUser(AbstractUser):
    ADMIN = 1
    STAFF = 2
    STUDENT = 3

    ROLE_CHOICES = (
        (ADMIN, "Admin"),
        (STAFF, "Staff"),
        (STUDENT, "Student"),
    )
    email = models.EmailField(unique=True)
    profile_picture = models.ImageField(
        upload_to="profile_pictures/", null=True, blank=True
    )
    role = models.PositiveSmallIntegerField(choices=ROLE_CHOICES, default=STUDENT)
    bio = models.TextField(_("about"), max_length=500, blank=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]


class Tag(models.Model):
    name = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.name


class Post(models.Model):
    title = models.CharField(max_length=200)
    content = models.TextField()
    tags = models.ManyToManyField(Tag, related_name="posts")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="posts")
    image = models.ImageField(upload_to="post_images/", null=True, blank=True)

    def __str__(self):
        return self.title


class Comment(models.Model):
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name="comments"
    )
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="comments")

    def __str__(self):
        return self.content[:20]


class Group(models.Model):
    name = models.CharField(max_length=200)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    users = models.ManyToManyField(CustomUser, related_name="discussion_groups")

    def __str__(self):
        return self.name
