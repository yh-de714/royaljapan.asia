from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.conf import settings
from royal.api.models import User, Product
from django.db.models import Q
import stripe

class UserLoginSerializer(TokenObtainPairSerializer):
    password = serializers.CharField(max_length=128, write_only=True)
    token = serializers.CharField(max_length=255, read_only=True)
    refresh = serializers.CharField(max_length=255, read_only=True)
    def validate(self, data):
        email = data.get("email", None)
        user = User.objects.filter(Q(email=email)).first()
        password = data.get("password", None)        
        if user is None:
            raise serializers.ValidationError(
                'not found'
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
                    products = stripe.Product.list(limit=10000)
                    for product in products:
                        price = stripe.Price.retrieve(product.default_price)
                        update_product = Product.objects.filter(Q(seller = user) & Q(product_id=product.id)).first()                       
                        update_product.description = product.description
                        update_product.image = product.images[0]
                        update_product.title = product.name
                        update_product.price_origin = price.unit_amount
                        update_product.description = product.description
                        update_product.save()
                except User.DoesNotExist:
                    raise serializers.ValidationError(
                        'password incorrect'
                    )
                return data
            else:
                raise serializers.ValidationError(
                    'password incorrect'
                )
            
class AdminLoginSerializer(TokenObtainPairSerializer):
    password = serializers.CharField(max_length=128, write_only=True)
    token = serializers.CharField(max_length=255, read_only=True)
    refresh = serializers.CharField(max_length=255, read_only=True)
    def validate(self, data):
        email = data.get("email", None)
        user = User.objects.filter(Q(email=email)).first()
        password = data.get("password", None)        
        if user is None:
            raise serializers.ValidationError(
                'A user with this email and password is not found.'
            )
        else:
            if user.check_password(password):
                try:
                    if user.is_superuser:
                        data = {}
                        refresh = self.get_token(user)
                        data['refresh'] = str(refresh)
                        data['token'] = str(refresh.access_token)
                        data['access_token_expires_in'] = settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME']
                        data['refresh_token_expires_in'] = settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME']
                        data['email']= user.email
                        data['username']=user.username
                        update_last_login(None, user)
                    else:
                        raise serializers.ValidationError(
                            'User with given username and password does not exists'
                        )
                except User.DoesNotExist:
                    raise serializers.ValidationError(
                        'User with given username and password does not exists'
                    )
                return data
            else:
                raise serializers.ValidationError(
                    'User with given username and password does not exists'
                )
        