from enum import unique
from re import L
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.base_user import BaseUserManager
from phonenumber_field.modelfields import PhoneNumberField
import uuid

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError(_('Email should be provided'))
        email = self.normalize_email(email)
        new_user = self.model(email=email, **extra_fields)
        new_user.set_password(password)
        new_user.save()
        return new_user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser should have is_staff as True'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser should have is_superuser as True'))
        if extra_fields.get('is_active') is not True:
            raise ValueError(_('Superuser should have is_active as True'))
        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    id = models.UUIDField(primary_key = True, default = uuid.uuid4, editable = False)
    username = models.CharField(max_length=200, unique=True)
    email = models.EmailField(max_length=200, unique=True)
    is_verified = models.BooleanField(default=False)
    phone_number = PhoneNumberField(null=False, unique=True)
    profile_pic = models.ImageField(default='default.jpg', upload_to='profile_pics')
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'phone_number']

    objects = CustomUserManager()

    def __str__(self) -> str:
        return f'<User: {self.email}>'


class URLCorsPermit(models.Model):
    url = models.CharField(max_length=300)

    def __str__(self) -> str:
        return f'Url Cors Permit: {self.url}'


