from django.shortcuts import get_object_or_404
from rest_framework import generics, status, mixins
from rest_framework.response import Response
from . import serializers
from .models import User
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from django.conf import settings
import jwt


class UserCreationView(generics.GenericAPIView):
    serializer_class = serializers.UserCreationSerializer
    parser_classes = [FormParser, MultiPartParser]
    def post(self, request):
        data = request.data
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            user_data = serializer.data
            user = get_object_or_404(User, email=user_data['email'])
            token = RefreshToken.for_user(user)
            current_site = get_current_site(request).domain
            relative_url = reverse('verify_email') 
            abs_url = 'http://'+current_site+relative_url+'?token='+str(token)
            email_body = 'Hello '+ user.username + ' Use the link below to verify your email \n' + abs_url
            email_subject = 'Verify your email'
            email_data = {'email_body': email_body, 'to_email': user.email, 'email_subject': email_subject}
            Util.send_email(email_data)
            return Response(data=serializer.data, status=status.HTTP_201_CREATED)
        return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class Users(generics.GenericAPIView):
    serializer_class = serializers.UserCreationSerializer
    permission_class = [IsAuthenticated]
    def get(self, request):
        user = request.user
        users = User.objects.all()
        new_users = []
        newer_users = []
        for u in users:
            if u != user:
                new_users.append(u)
        for su in new_users:
            if not su.is_superuser:
                newer_users.append(su) 

        serializer = self.serializer_class(instance=newer_users, many=True)
        return Response(data=serializer.data, status=status.HTTP_200_OK)


class DeleteUser(generics.GenericAPIView):
    serializer_class = serializers.UserCreationSerializer
    permission_class = [IsAuthenticated, IsAdminUser]
    def delete(self, request, user_id):
        user = get_object_or_404(User, pk=user_id)
        if user:
            user.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response(status=status.HTTP_404_NOT_FOUND)


class UpdateUser(mixins.UpdateModelMixin, generics.GenericAPIView):
    serializer_class = serializers.UserUpdateSerializer
    parser_classes = [FormParser, MultiPartParser]
    permission_class = [IsAuthenticated]
    def put(self, request, user_id):
        data = request.data
        user = get_object_or_404(User, pk=user_id)
        serializer = self.serializer_class(data=data, instance=user)
        if serializer.is_valid():
            serializer.save()
            return Response(data=serializer.data, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_404_NOT_FOUND)


class VerifyEmail(generics.GenericAPIView):
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
                return Response({'verification_status': 'Email successfully verified'}, status=status.HTTP_200_OK)
            return Response({'verification_status': 'Email already verified'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as err:
            return Response({'error': 'Email verification link Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.DecodeError as err:
            return Response({'error': 'Invalid Verification Token'}, status=status.HTTP_400_BAD_REQUEST)


class UserChangePasswordView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = serializers.UserChangePasswordSerializer
    def post(self, request):
        user = request.user
        data = request.data
        serializer = self.serializer_class(data=data, context={'user': user})
        if serializer.is_valid():
            return Response({'msg': 'Password changed successfully'}, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_400_BAD_REQUEST)


class SendPasswordResetEmail(generics.GenericAPIView):
    serializer_class = serializers.SendPasswordResetEmailSerializer
    def post(self, request):
        data = request.data
        serializer = self.serializer_class(data=data, context={'request':request})
        if serializer.is_valid():
            return Response({'msg': 'Email has been sent to reset password'}, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordView(generics.GenericAPIView):
    serializer_class = serializers.ResetPasswordSerializer
    def post(self, request, uid, token):
        data = request.data
        serializer = self.serializer_class(data=data, context={'uid': uid, 'token': token})
        if serializer.is_valid():
            return Response({'msg': 'Password reset successfully'}, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_400_BAD_REQUEST)

