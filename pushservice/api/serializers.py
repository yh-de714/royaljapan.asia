from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.conf import settings
from pushservice.api.models import User
from django.db.models import Q

class UserLoginSerializer(TokenObtainPairSerializer):
    password = serializers.CharField(max_length=128, write_only=True)
    token = serializers.CharField(max_length=255, read_only=True)
    refresh = serializers.CharField(max_length=255, read_only=True)
    def validate(self, data):
        username = data.get("username", None)
        user = User.objects.filter(Q(username=username)).first()
        password = data.get("password", None)        
        if user is None:
            raise serializers.ValidationError(
                'A user with this username and password is not found.'
            )
        else:
            if user.check_password(password):
                try:
                    data = {}
                    refresh = self.get_token(user)
                    data['refresh'] = str(refresh)
                    data['token'] = str(refresh.access_token)
                    data['access_token_expires_in'] = settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME']
                    data['refresh_token_expires_in'] = settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME']
                    data['email']= user.email
                    data['username']=user.username
                    update_last_login(None, user)
                except User.DoesNotExist:
                    raise serializers.ValidationError(
                        'User with given username and password does not exists'
                    )
                return data
            else:
                raise serializers.ValidationError(
                    'User with given username and password does not exists'
                )
        