from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from royal.api.models import *
from rest_framework import status
from rest_framework.generics import CreateAPIView, RetrieveAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from royal.api.serializers import UserLoginSerializer
from royal.api.models import *
from django.db.models import Q, Count

# from django.db import connection
from rest_framework.views import APIView
from django.utils import timezone

import requests 
import json 
import base64
import time


class Command(BaseCommand):
    help = "Closes the specified poll for voting"


    def handle(self, *args, **options):
        
        users = User.objects.all()

        for m_user in users:
            m_products = Product.objects.filter(product_user=m_user, store_type="Yahoo")

            # find duplicate products for amznurl fields and store fields
            duplicate_products = m_products.values('amznurl', 'store').annotate(count=Count('id')).filter(count__gt=1)
            
            for duplicate_product in duplicate_products:
                print("Duplicate Product: ", duplicate_product)

                # delete duplicate products except the first one
                duplicates = m_products.filter(Q(amznurl=duplicate_product['amznurl']) & Q(store=duplicate_product['store']))
                duplicates.exclude(id=duplicates.first().id).delete()