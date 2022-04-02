from rest_framework import serializers
from .models import User
from phonenumber_field.serializerfields import PhoneNumberField


class UserCreationSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=200)
    email = serializers.EmailField(max_length=200)
    is_verified = serializers.BooleanField(default=False, required=False, read_only=True)
    phone_number = PhoneNumberField(allow_null=False, allow_blank=False)
    password = serializers.CharField(max_length=100, write_only=True)
    profile_pic = serializers.ImageField(default='default.jpg')

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'phone_number', 'is_verified', 'password', 'profile_pic']

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
