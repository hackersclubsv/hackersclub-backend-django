from datetime import datetime

from django.contrib.auth.models import AbstractUser
from django.db import DatabaseError, models
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
        default="https://hackersclub-production-user-content-us-west-1.s3.us-west-1.amazonaws.com/default_profile_picture.png"
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

    def save(self, *args, **kwargs):
        # Convert username to lowercase and remove spaces
        self.username = self.username.lower().replace(" ", "_")
        super(CustomUser, self).save(*args, **kwargs)


class TimeStampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


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
    slug = models.SlugField(max_length=255, unique=True, blank=True)
    tags = models.ManyToManyField(Tag, related_name="posts")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="posts")
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True)
    is_deleted = models.BooleanField(default=False, db_index=True)
    is_sticky = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if not self.pk or self.title_changed():
            original_slug = slugify(self.title)
            unique_slug = original_slug

            # Check if a post with the original slug exists
            post_with_original_slug = Post.objects.filter(slug=original_slug).first()

            # If the post exists and it's not the current instance, append datetime
            if post_with_original_slug and post_with_original_slug.pk != self.pk:
                date_str = datetime.now().strftime("%Y%m%d%H%M%S")
                unique_slug = f"{original_slug}-{date_str}"

            self.slug = unique_slug
        try:
            super().save(*args, **kwargs)
        except DatabaseError:
            print("Database error encountered while saving the Post.")
        except Exception as e:
            print(f"Unexpected error occurred while saving the Post.: {str(e)}")

    def title_changed(self):
        try:
            orig = Post.objects.get(pk=self.pk)
            return orig.title != self.title
        except Post.DoesNotExist:
            return False

    def __str__(self):
        return self.title


class Comment(models.Model):
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name="comments"
    )
    is_deleted = models.BooleanField(default=False, db_index=True)
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="comments")
    parent = models.ForeignKey("self", null=True, blank=True, on_delete=models.SET_NULL)
    slug = models.SlugField(max_length=255, unique=True, blank=True)

    def save(self, *args, **kwargs):
        if not self.slug or self.content_changed():
            original_slug = slugify(self.content[:50])
            unique_slug = original_slug

            # Check if a comment with the original slug exists
            comment_with_original_slug = Comment.objects.filter(
                slug=original_slug
            ).first()

            # If the comment exists and it's not the current instance, append datetime
            if comment_with_original_slug and comment_with_original_slug.pk != self.pk:
                date_str = datetime.now().strftime("%Y%m%d%H%M%S")
                unique_slug = f"{original_slug}-{date_str}"

            self.slug = unique_slug
        try:
            super().save(*args, **kwargs)
        except DatabaseError:
            print("Database error encountered while saving the Comment.")
        except Exception as e:
            print(f"Unexpected error occurred while saving the Comment.: {str(e)}")

    def content_changed(self):
        try:
            orig = Comment.objects.get(pk=self.pk)
            return orig.content != self.content
        except Comment.DoesNotExist:
            return False

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


class PostVote(models.Model):
    UPVOTE = "upvote"
    DOWNVOTE = "downvote"

    VOTE_CHOICES = [(UPVOTE, "Upvote"), (DOWNVOTE, "Downvote")]

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    post = models.ForeignKey(Post, on_delete=models.CASCADE)
    vote = models.CharField(max_length=10, choices=VOTE_CHOICES)

    class Meta:
        unique_together = ("user", "post")


class CommentVote(models.Model):
    UPVOTE = "upvote"
    DOWNVOTE = "downvote"

    VOTE_CHOICES = [(UPVOTE, "Upvote"), (DOWNVOTE, "Downvote")]

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    comment = models.ForeignKey(Comment, on_delete=models.CASCADE)
    vote = models.CharField(max_length=10, choices=VOTE_CHOICES)

    class Meta:
        unique_together = ("user", "comment")
