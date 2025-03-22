from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from royal.api.models import *
from rest_framework import status
from rest_framework.generics import CreateAPIView, RetrieveAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from royal.api.serializers import UserLoginSerializer
from royal.api.models import *
from django.db.models import Q

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
        user = User.objects.get(username="test")
        sleep_time = 10
        db_amznurl_array = [f"https://www.amazon.co.jp/dp/B001GHIPDA?language=ja_JP"]
        amzn_price_request_array = [
            {
                "uri": "/products/pricing/v0/items/" + item[28:-15] + "/offers",
                "method": "GET",
                "MarketplaceId": "A1VC38T7YXB528",
                "ItemCondition": "New",
                "CustomerType": "Consumer"
            }
                    for item in db_amznurl_array]
        
        print(db_amznurl_array)
        db_user = User.objects.filter(username=user.username).first()
        amzn_get_access_token_entrypoint = "https://api.amazon.com/auth/o2/token"
        amzn_client_id = db_user.amazon_client_id
        amzn_client_secret = db_user.amazon_client_secret
        amzn_access_token = db_user.amazon_access_token
        amzn_refresh_token = db_user.amazon_refresh_token
        amzn_grant_type = "refresh_token"
        amzn_get_price_data_header = {
            "Authorization": "Bearer " + amzn_access_token,
            "Content-Type": "application/json",
            "x-amz-access-token": amzn_access_token,
        }
        amzn_price_entrypoint = "https://sellingpartnerapi-fe.amazon.com/batches/products/pricing/v0/itemOffers"
        response_amzn_price = requests.post(amzn_price_entrypoint, headers=amzn_get_price_data_header, data=json.dumps({"requests": amzn_price_request_array}))
        amzn_price_data_json = response_amzn_price.json()
        time.sleep(sleep_time)
        print("Get amazon price data")
        # print(amzn_price_data_json)
        try:
            if amzn_price_data_json['errors'][0]["code"] == "Unauthorized":
                amzn_get_access_token_credentials = base64.b64encode(f"{amzn_client_id}:{amzn_client_secret}".encode()).decode()
                amzn_get_access_token_header = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": f"Basic {amzn_get_access_token_credentials}"
                }
                amzn_get_access_token_data = {
                    "grant_type": amzn_grant_type,
                    "refresh_token": amzn_refresh_token
                }
                try:
                    amzn_get_access_token_response = requests.post(amzn_get_access_token_entrypoint, headers=amzn_get_access_token_header, data=amzn_get_access_token_data)
                    amzn_access_token = amzn_get_access_token_response.json()["access_token"]
                    print("Get amazon access token")
                    time.sleep(sleep_time)
                    db_user.amazon_access_token = amzn_access_token
                    db_user.save()
                    amzn_get_price_data_header = {
                        "Authorization": "Bearer " + amzn_access_token,
                        "Content-Type": "application/json",
                        "x-amz-access-token": amzn_access_token,
                    }
                    amzn_price_entrypoint = "https://sellingpartnerapi-fe.amazon.com/batches/products/pricing/v0/itemOffers"
                    response_amzn_price = requests.post(amzn_price_entrypoint, headers=amzn_get_price_data_header, data=json.dumps({"requests": amzn_price_request_array}))
                    amzn_price_data_json = response_amzn_price.json()
                    time.sleep(sleep_time)
                    print("Get amazon price data again")
                    print(amzn_price_data_json)
                except Exception as e:
                    print("Amazon Refresh Token Request Error:", str(e))
                    print('amazon app error')
                    db_user.amazon_enable = False
                    db_user.save()
                    res_data = {
                        'err_type': 'API',
                        'detail': 'Amazon',
                        'success': False,
                    }
                    return Response(data=res_data, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print("")
   
        amzn_price_response = amzn_price_data_json['responses']
        amzn_price_response_price_qty_array = []

        for item in amzn_price_response:
            try:
                if item['body']['payload']['Identifier']['ItemCondition'] == 'New':

                    lowest_price = 0
                    print(item['body']['payload']['Summary'])

                    for offer in item['body']['payload']['Summary']['BuyBoxPrices']:
                        if offer["condition"] == "New" and lowest_price == 0:
                            lowest_price = (int)(offer['ListingPrice']['Amount'])

                    print(lowest_price)
                    amzn_price_response_price_qty_array.append(
                        {
                            "qty": True if item['body']['payload']['status'] == 'Success' else False,
                            "price": lowest_price,
                        }
                    )
                else:
                    amzn_price_response_price_qty_array.append(
                        {
                            "qty": False,
                            "price": 0
                        }
                    )
            except Exception as e:
                print("Amazon Price Data Error:", str(e))
                amzn_price_response_price_qty_array.append(
                    {
                        "qty": False,
                        "price": 0
                    }
                )
