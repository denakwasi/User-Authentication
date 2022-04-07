from ast import Pass
from rest_framework import serializers
# from .models import URLCorsPermit
from phonenumber_field.serializerfields import PhoneNumberField
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util
import jwt
from django.conf import settings
from django.contrib.auth import get_user_model

User = get_user_model()

class UserCreationSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=200)
    email = serializers.EmailField(max_length=200)
    is_verified = serializers.BooleanField(default=False, required=False, read_only=True)
    phone_number = PhoneNumberField(allow_null=False, allow_blank=False)
    password = serializers.CharField(max_length=100, write_only=True)
    profile_pic = serializers.ImageField(default='profile_pics/default.jpg')

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'phone_number', 'is_verified', 'is_superuser', 'password', 'profile_pic']

    def validate(self, attrs):
        username_exists = User.objects.filter(username=attrs['username']).exists()
        email_exists = User.objects.filter(username=attrs['email']).exists()
        phone_number_exists = User.objects.filter(username=attrs['phone_number']).exists()

        if username_exists:
            raise serializers.ValidationError(detail='User with username already exists')

        if email_exists:
            raise serializers.ValidationError(detail='User with email already exists')

        if phone_number_exists:
            raise serializers.ValidationError(detail='User with phone number already exists')

        return super().validate(attrs)

    def create(self, validated_data):
        user = User.objects.create(
            **validated_data
        )
        user.set_password(validated_data['password'])
        user.save()
        return user


class UserUpdateSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=200, allow_null=True, allow_blank=True)
    email = serializers.EmailField(max_length=200, allow_null=False, allow_blank=False)
    phone_number = PhoneNumberField(allow_null=True, allow_blank=True)
    profile_pic = serializers.ImageField(required=False)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'phone_number', 'profile_pic']


class UserChangePasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=100, style={'input_type':'password'}, write_only=True)
    password_confirm = serializers.CharField(max_length=100, style={'input_type':'password'}, write_only=True)

    class Meta:
        model = User
        fields = ['password', 'password_confirm']

    def validate(self, attrs):
        password = attrs.get('password')
        password_confirm = attrs.get('password_confirm')
        user  = self.context.get('user')
        if password != password_confirm:
            raise serializers.ValidationError('Password and Confirm Password do not match')
        user.set_password(password)
        user.save()
        return attrs


class SendPasswordResetEmailSerializer(serializers.ModelSerializer):
    email = serializers.CharField(max_length=150)

    class Meta:
        model = User
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        request = self.context.get('request')
        if User.objects.all().filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request).domain
            print('CURRENT', current_site)
            relative_url = reverse('reset_password_email') 
            link = 'http://'+current_site+'/auth/reset-password/'+'?uid='+uid+'/'+'?token='+str(token)
            email_body = 'Hello '+ user.username + ' Use the link below to reset your password \n' + link
            email_subject = 'Reset your Password'
            email_data = {'email_body': email_body, 'to_email': user.email, 'email_subject': email_subject}
            Util.send_email(email_data)
            return attrs
        raise serializers.ValidationError('You are not a registered user')


class ResetPasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=100, style={'input_type':'password'}, write_only=True)
    password_confirm = serializers.CharField(max_length=100, style={'input_type':'password'}, write_only=True)

    class Meta:
        model = User
        fields = ['password', 'password_confirm']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password_confirm = attrs.get('password_confirm')
            if password != password_confirm:
                raise serializers.ValidationError('Password and Confirm Password do not match')
            token  = self.context.get('token')  # token
            uid  = self.context.get('uid')      # uid
            pk = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=pk)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError('Token is not valid or expired')
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as err:
            PasswordResetTokenGenerator().check_token(user, token)
            raise serializers.ValidationError('Token is not valid or expired')



# class URLCorsPermitSerializer(serializers.ModelSerializer):
#     url = serializers.CharField(max_length=300)

#     class Meta:
#         model = URLCorsPermit
#         fields = ['id', 'url']