from django.shortcuts import get_object_or_404, redirect
from rest_framework import generics, status, mixins
from rest_framework.response import Response
from . import serializers
from .models import AccessTokenExp, User
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from django.conf import settings
import jwt

from datetime import timedelta

# Create A User -> Signup User
class UserCreationView(generics.GenericAPIView):
    serializer_class = serializers.UserCreationSerializer
    parser_classes = [FormParser, MultiPartParser]
    def post(self, request):
        data = request.data
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            serializer.save()
            # ----------Create access token duration--------
            # import datetime
            # if AccessTokenExp.DoesNotExist:
            #     tk = AccessTokenExp.objects.all()
            #     if len(tk) == 0:
            #         AccessTokenExp.objects.create(token_exp_time=str(datetime.timedelta(minutes=3)), refresh_exp_time=str(datetime.timedelta(minutes=5)))
            # ----------------------------------------------
            user_data = serializer.data
            user = get_object_or_404(User, email=user_data['email'])
            token = RefreshToken.for_user(user)
            current_site = get_current_site(request).domain
            relative_url = reverse('verify_email') 
            abs_url = 'http://'+current_site+relative_url+'?token='+str(token)  # '+current_site+relative_url+'
            email_body = 'Hello '+ user.username + '\nUse the link below to verify your email \n' + abs_url
            email_subject = 'Verify your email'
            email_data = {'email_body': email_body, 'to_email': user.email, 'email_subject': email_subject}
            Util.send_email(email_data)
            return Response(data=serializer.data, status=status.HTTP_201_CREATED)
        return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)


settings.SIMPLE_JWT.update({'ACCESS_TOKEN_LIFETIME': timedelta(minutes=5)})
print(settings.SIMPLE_JWT.get('ACCESS_TOKEN_LIFETIME'))


# Get all Users except the logged in user
class Users(generics.GenericAPIView):
    serializer_class = serializers.UserCreationSerializer
    permission_classes = [IsAuthenticated]
    def get(self, request):
        # 
        
        user = request.user
        users = User.objects.all()
        new_users = []
        if user.is_superuser:
            for su in users:
                if su != user:
                    new_users.append(su)
        elif not user.is_superuser:
            for u in users:
                if u != user:
                    if not u.is_superuser:
                        new_users.append(u)

        serializer = self.serializer_class(instance=new_users, many=True)
        return Response(data=serializer.data, status=status.HTTP_200_OK)



class UserDetail(generics.GenericAPIView):
    serializer_class = serializers.UserCreationSerializer
    permission_classes = [IsAuthenticated]
    def get(self, request, user_id):
        user = get_object_or_404(User, pk=user_id)
        serializer = self.serializer_class(instance=user)
        return Response(data=serializer.data, status=status.HTTP_200_OK)


# Delete a User
class DeleteUser(generics.GenericAPIView):
    serializer_class = serializers.UserCreationSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]
    parser_classes = [FormParser, MultiPartParser]
    def delete(self, request, user_id):
        user = get_object_or_404(User, pk=user_id)
        if user:
            user.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response(status=status.HTTP_404_NOT_FOUND)


# Update a User
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


# Verify a signup User
class VerifyEmail(generics.GenericAPIView):
    serializer_class = serializers.UserCreationSerializer
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
                res = 'http://localhost:3000/auth/verified'
                return redirect(res)    # Response({'verification_status': 'Email successfully verified'}, status=status.HTTP_200_OK)
            return Response({'verification_status': 'Email already verified'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as err:
            return Response({'error': 'Email verification link Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.DecodeError as err:
            return Response({'error': 'Invalid Verification Token'}, status=status.HTTP_400_BAD_REQUEST)


# Change a User's Password
class UserChangePasswordView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [FormParser, MultiPartParser]
    serializer_class = serializers.UserChangePasswordSerializer
    def post(self, request):
        user = request.user
        data = request.data
        serializer = self.serializer_class(data=data, context={'user': user})
        if serializer.is_valid():
            return Response({'msg': 'Password changed successfully'}, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_400_BAD_REQUEST)


# Send an Email to a User requesting to reset their password
class SendPasswordResetEmail(generics.GenericAPIView):
    serializer_class = serializers.SendPasswordResetEmailSerializer
    def post(self, request):
        data = request.data
        serializer = self.serializer_class(data=data, context={'request':request})
        if serializer.is_valid():
            return Response({'msg': 'Email has been sent to reset password'}, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_400_BAD_REQUEST)


# Reset the User's password -> Forgotten Password
class ResetPasswordView(generics.GenericAPIView):
    parser_classes = [FormParser, MultiPartParser]
    serializer_class = serializers.ResetPasswordSerializer
    def post(self, request):
        uid = request.GET.get('uid').split('/?token=')[0]
        token = request.GET.get('uid').split('/?token=')[1]
        data = request.data
        serializer = self.serializer_class(data=data, context={'uid': uid, 'token': token})
        if serializer.is_valid():
            return Response({'msg': 'Password reset successfully'}, status=status.HTTP_200_OK)
        return Response({'msg': 'Password has already been reset or password reset token expired'}, status=status.HTTP_400_BAD_REQUEST)


# URLs Cors Permit to access API Endpoints
# class URLCorsPermitView(generics.GenericAPIView):
#     parser_classes = [FormParser, MultiPartParser]
#     permission_classes = [IsAdminUser, IsAuthenticated]
#     serializer_class = serializers.URLCorsPermitSerializer
#     def post(self, request):
#         data = request.data
#         serializer = self.serializer_class(data=data)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(data=serializer.data, status=status.HTTP_200_OK)
#         return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # def get(self, request):
    #     URLs = settings.CORS_ALLOWED_ORIGINS
    #     UCP = URLCorsPermit.objects.all()
    #     for url in UCP:
    #         URLs.append(url.url)
    #     serializer = self.serializer_class(instance=UCP, many=True)
    #     return Response(data=serializer.data, status=status.HTTP_200_OK)


# Update or Delete URL Cors Headers Permit
# class UpdateOrDeleteURLCorsPermitView(generics.GenericAPIView):
#     parser_classes = [FormParser, MultiPartParser]
#     permission_classes = [IsAdminUser, IsAuthenticated]
#     serializer_class = serializers.URLCorsPermitSerializer
#     def put(self, request, url_id):
#         data = request.data
#         url = get_object_or_404(URLCorsPermit, pk=url_id)
#         serializer = self.serializer_class(data=data, instance=url)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(data=serializer.data, status=status.HTTP_200_OK)
#         return Response(status=status.HTTP_404_NOT_FOUND)

#     def delete(self, request, url_id):
#         url = get_object_or_404(URLCorsPermit, pk=url_id)
#         if url:
#             url.delete()
#             return Response(status=status.HTTP_204_NO_CONTENT)
#         return Response(status=status.HTTP_404_NOT_FOUND)


# Make a User Admin
class MakeUserAdmin(generics.GenericAPIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    def post(self, request, admin_to_be_id):
        users = User.objects.all()
        user = User.objects.get(id=admin_to_be_id)
        if user:
            if not user.is_superuser:
                user.is_superuser = True
                user.save()

                email_body = 'Congratulation! '+ user.username + '\nYou have been made an Admin.\nYou now have authority to gain limitless access'
                email_subject = 'Welcome A New Admin'
                email_data = {'email_body': email_body, 'to_email': user.email, 'email_subject': email_subject}
                Util.send_email(email_data)

                return Response({'msg': f'User with email {user.email} is now an Admin'}, status=status.HTTP_200_OK)
            elif user.is_superuser:
                return Response({'msg': f'User with email {user.email} is already an Admin'}, status=status.HTTP_304_NOT_MODIFIED)
                    
        return Response(status=status.HTTP_417_EXPECTATION_FAILED) 


# Revoke Admin Right
class MakeUserNonAdmin(generics.GenericAPIView):
    # serializer_class = serializers.UserCreationSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]
    def post(self, request, admin_id):
        users = User.objects.all()
        user = User.objects.get(id=admin_id)
        if user:
            if user.is_superuser:
                user.is_superuser = False
                user.save()

                email_body = 'Sorry! '+ user.username + '\nYou are now not an Admin.\nYou are back to being a normal user.'
                email_subject = 'Admin Right Revoked'
                email_data = {'email_body': email_body, 'to_email': user.email, 'email_subject': email_subject}
                Util.send_email(email_data)

                return Response({'msg': f'User with email {user.email} is now not an Admin'}, status=status.HTTP_200_OK)
            elif not user.is_superuser:
                return Response({'msg': f'User with email {user.email} is not an Admin'}, status=status.HTTP_304_NOT_MODIFIED)
                    
        return Response(status=status.HTTP_417_EXPECTATION_FAILED) 



class AccessTokenExpView(generics.GenericAPIView):
    serializer_class = serializers.AccessTokenExpSerializer
    parser_classes = [FormParser, MultiPartParser]
    # permission_classes = [IsAuthenticated, IsAdminUser]
    def put(self, request):
        data = request.data
        first_tk = AccessTokenExp.objects.all()[:1].get()
        tk = get_object_or_404(AccessTokenExp, pk=first_tk.id)
        serializer = self.serializer_class(data=data, instance=tk)
        if serializer.is_valid():
            serializer.save()
            return Response({'status': 200, 'msg': 'Access token duration set successfully'})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        access_token = AccessTokenExp.objects.all()
        serializer = self.serializer_class(instance=access_token, many=True)
        return Response(data=serializer.data, status=status.HTTP_200_OK)
