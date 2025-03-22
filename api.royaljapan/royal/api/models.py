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
  
    def create_user(self, email, password=None):
        """
        Create and return a `User` with an username and password.
        """
        if not email:
            raise ValueError('Users Must Have an username address')

        user = self.model(
            email=email,
            username=""
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password):
        """
        Create and return a `User` with superuser (admin) permissions.
        """
        if password is None:
            raise TypeError('Superusers must have a password.')

        user = self.create_user(email, password)
        user.is_superuser = True
        # user.status = 1
        user.save()
        return user
    
class User(AbstractBaseUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)    
    email = models.EmailField(verbose_name='email address', unique=True, max_length=255)
    username = models.CharField(max_length=255, blank=True, null=True, default="")
    USERNAME_FIELD = 'email'
    REQUIRED_FIELD = []
    is_superuser = models.BooleanField(default=False)
    objects = UserManager()
    def __str__(self):
        return self.username

    class Meta:
        db_table = "User"

class Product(models.Model):
    id = models.AutoField(primary_key=True)
    seller = models.ForeignKey(User, on_delete=models.CASCADE, related_name="fee_user", default="")
    price_origin = models.IntegerField(default=0)
    price_sell = models.IntegerField(default=0)
    price_id = models.CharField(max_length=60, blank=True, default="", null=True)
    product_id = models.CharField(max_length=60, blank=True, default="", null=True)
    description = models.CharField(max_length=1000, blank=True, default="", null=True)
    title = models.CharField(max_length=255, blank=True, default="", null=True)
    image = models.CharField(max_length=255, blank=True, default="", null=True)
    image1 = models.CharField(max_length=255, blank=True, default="", null=True)
    image2 = models.CharField(max_length=255, blank=True, default="", null=True)
    image3 = models.CharField(max_length=255, blank=True, default="", null=True)
    package = models.CharField(max_length=60, blank=True, default="", null=True)
    sold_count = models.IntegerField(default=0)

class Coupon(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="seller", default="")
    code = models.CharField(max_length=16, blank=True, null=True, default="")
    percent = models.IntegerField(default=0)


class Sold(models.Model):
    id = models.AutoField(primary_key=True)
    product_id = models.ForeignKey(Product, on_delete=models.CASCADE, related_name="sold_product", default="")
    coupon_id = models.ForeignKey(Coupon, on_delete=models.CASCADE, null=True, blank=True, related_name="coupon_id", default="")

class PageSetting(models.Model):
    id = models.AutoField(primary_key=True)
    key = models.CharField(max_length=32, blank=True, null=True, default="")
    value = models.CharField(max_length=1000, blank=True, null=True, default="")
    