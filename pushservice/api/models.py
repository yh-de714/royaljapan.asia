from typing import Tuple
import uuid
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.db import models
from django.utils import tree
import stripe
from django.conf import settings
from stripe.api_resources import subscription
from django.utils import timezone

class UserManager(BaseUserManager):
  
    def create_user(self, username, password=None):
        """
        Create and return a `User` with an username and password.
        """
        if not username:
            raise ValueError('Users Must Have an username address')

        user = self.model(
            username=username,
            email=username
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, password):
        """
        Create and return a `User` with superuser (admin) permissions.
        """
        if password is None:
            raise TypeError('Superusers must have a password.')

        user = self.create_user(username, password)
        user.is_superuser = True
        user.status = 1
        user.save()
        return user
    
class User(AbstractBaseUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255, unique=False, blank=True, null=True, default="")
    email = models.EmailField(verbose_name='email address', max_length=255, unique=False)
    ngwords = models.TextField(max_length=255, unique=False, blank=True, null=True, default="")
    ng_asin_codes = models.TextField(blank=True, null=True, default="")
    ng_titles = models.TextField(blank=True, null=True, default="")
    ng_descriptions = models.TextField(blank=True, null=True, default="")
    created_at = models.DateTimeField(default=timezone.now)

    amazon_client_id = models.CharField(max_length=255, default="")
    amazon_client_secret = models.CharField(max_length=255, default="")
    amazon_refresh_token = models.CharField(max_length=255, default="")
    amazon_access_token = models.CharField(max_length=255, default="")
    amazon_enable = models.BooleanField(default=False)

    yahoo_store_id = models.CharField(max_length=255, unique=False, blank=True, null=True, default="")
    yahoo_store_name = models.CharField(max_length=255, unique=False, blank=True, null=True, default="")
    yahoo_client_id = models.CharField(max_length=255, unique=False, blank=True, null=True, default="")
    yahoo_client_secret = models.CharField(max_length=255, unique=False, blank=True, null=True, default="")
    yahoo_refresh_token = models.CharField(max_length=255, unique=False, blank=True, null=True, default="")
    yahoo_access_token = models.CharField(max_length=255, unique=False, blank=True, null=True, default="")
    yahoo_update_time = models.DateTimeField(default=timezone.datetime(2024,2,27))
    yahoo_register_time = models.DateTimeField(default=timezone.datetime(2024,2,27))
    yahoo_enable = models.BooleanField(unique=False, default=False)

    qoo10_username = models.CharField(max_length=255, unique=False, blank=True, null=True, default="")
    qoo10_password = models.CharField(max_length=255, unique=False, blank=True, null=True, default="")
    qoo10_store_name = models.CharField(max_length=255, unique=False, blank=True, null=True, default="")
    qoo10_api_key = models.CharField(max_length=255, unique=False, blank=True, null=True, default="")
    qoo10_sak = models.CharField(max_length=255, unique=False, blank=True, null=True, default="")
    qoo10_update_time = models.DateTimeField(default=timezone.datetime(2024,2,27))
    qoo10_register_time = models.DateTimeField(default=timezone.datetime(2024,2,27))
    qoo10_enable = models.BooleanField(unique=False, default=False)
    remain_score = models.IntegerField(default=5)
    seller_count = models.IntegerField(default=2)
    oneseller = models.IntegerField(default=True)
    multi = models.BooleanField(default=True)
    yahoo_auto = models.IntegerField(default=-1)
    qoo10_auto = models.IntegerField(default=-1)
    USERNAME_FIELD = 'username'
    REQUIRED_FIELD = []    
    objects = UserManager()
    def __str__(self):
        return self.username

    class Meta:
        db_table = "User"


class Fee(models.Model):
    id = models.AutoField(primary_key=True)
    fee_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="fee_user", default="")
    multi_rate = models.IntegerField(default=100)
    ship_fee = models.IntegerField(default=0)
    fee = models.IntegerField(default=0)
    price = models.IntegerField(default=0)
    fee_type = models.BooleanField(default=True)
    store_type = models.CharField(max_length=50, default="Yahoo")

class Product(models.Model):
    id = models.AutoField(primary_key=True)
    product_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="product_user", default="")
    amznurl = models.CharField(max_length=500, default="")
    price = models.IntegerField(default=0)
    store = models.CharField(max_length=50, default="")
    store_type = models.CharField(max_length=50, default="Yahoo")
    code = models.CharField(max_length=255, default="")
    path = models.CharField(max_length=255, default="")
    second_sub_cat = models.CharField(max_length=255, default="")
    quanty = models.IntegerField(default=5)
    created_at = models.DateTimeField(default=timezone.now)
    qty = models.BooleanField(default=True)

class Notification(models.Model):
    id = models.AutoField(primary_key=True)
    title = models.CharField(max_length=255, default="")
    content = models.TextField(default="")
    url = models.CharField(max_length=255, default="")
    created_at = models.DateField(default=timezone.now)


class PushServiceGlobalSetting(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255, default="default")
    ng_asin_codes = models.TextField(blank=True, null=True, default="")
    ng_titles = models.TextField(blank=True, null=True, default="")
    ng_descriptions = models.TextField(blank=True, null=True, default="")
    created_at = models.DateTimeField(default=timezone.now)