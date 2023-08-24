from datetime import datetime

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.text import slugify
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
    profile_picture = models.URLField(
        default="https://coengage-bucket.s3.us-west-1.amazonaws.com/default_profile_picture.png"
    )
    role = models.PositiveSmallIntegerField(choices=ROLE_CHOICES, default=STUDENT)
    bio = models.TextField(_("about"), max_length=500, blank=True)
    is_verified = models.BooleanField(default=False)
    otp = models.CharField(max_length=32, blank=True, null=True)
    otp_created_at = models.DateTimeField(blank=True, null=True)
    otp_expiration = models.DateTimeField(blank=True, null=True)
    otp_attempts = models.IntegerField(default=0)
    otp_attempts_timestamp = models.DateTimeField(blank=True, null=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]


class Category(models.Model):
    name = models.CharField(max_length=100, unique=True, db_index=True)

    def __str__(self):
        return self.name


class Tag(models.Model):
    name = models.CharField(max_length=50, unique=True, db_index=True)

    def __str__(self):
        return self.name


class Post(models.Model):
    title = models.CharField(max_length=200, blank=False, null=False)
    content = models.TextField(blank=False, null=False)
    slug = models.SlugField(unique=True, blank=True)  
    tags = models.ManyToManyField(Tag, related_name="posts")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="posts")
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True)
    is_deleted = models.BooleanField(default=False)
    is_sticky = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        original_slug = slugify(self.title)
        unique_slug = original_slug
        date_str = datetime.now().strftime("%Y%m%d%H%M%S")

        if Post.objects.filter(slug=original_slug).exists():
            unique_slug = f"{original_slug}-{date_str}"

        self.slug = unique_slug
        super().save(*args, **kwargs)

    def __str__(self):
        return self.title


class Vote(models.Model):
    UPVOTE = "upvote"
    DOWNVOTE = "downvote"

    VOTE_CHOICES = [(UPVOTE, "Upvote"), (DOWNVOTE, "Downvote")]

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    post = models.ForeignKey(Post, on_delete=models.CASCADE)
    vote = models.CharField(max_length=10, choices=VOTE_CHOICES)

    class Meta:
        unique_together = ("user", "post")


class Comment(models.Model):
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name="comments"
    )
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="comments")
    parent = models.ForeignKey("self", null=True, blank=True, on_delete=models.SET_NULL)

    def __str__(self):
        return self.content[:20]


class Image(models.Model):
    url = models.URLField()
    post = models.ForeignKey(
        "Post", on_delete=models.CASCADE, null=True, blank=True, related_name="images"
    )
    comment = models.ForeignKey(
        "Comment",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="images",
    )


class Group(models.Model):
    name = models.CharField(max_length=200)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    users = models.ManyToManyField(CustomUser, related_name="discussion_groups")

    def __str__(self):
        return self.name
