from rest_framework import status
from rest_framework.generics import CreateAPIView, RetrieveAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from pushservice.api.serializers import UserLoginSerializer
from pushservice.api.models import *
from django.db import transaction
from django.db.models import Q

# from django.db import connection
from rest_framework.views import APIView
from django.utils import timezone

import requests 
import json 
import base64
import time

class UserLoginView(RetrieveAPIView):
    permission_classes = (AllowAny,)
    serializer_class = UserLoginSerializer

    def post(self, request):
        try:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = User.objects.filter(Q(username=request.data['username'])).first()
            response = {
                'status code': status.HTTP_200_OK,
                'token': serializer.data['token'],
                'refresh': serializer.data['refresh'],
                # 'userstatus': serializer.data['userstatus'],
                'email': user.email,
                'username': user.username,
                'name': user.name,
                'amazon_client_id': user.amazon_client_id,
                'amazon_client_secret': user.amazon_client_secret,
                'amazon_refresh_token': user.amazon_refresh_token,
                'amazon_access_token': user.amazon_access_token,
                'amazon_enable': user.amazon_enable,
                'yahoo_store_id': user.yahoo_store_id,
                'yahoo_store_name': user.yahoo_store_name,
                'yahoo_client_id': user.yahoo_client_id,
                'yahoo_client_secret': user.yahoo_client_secret,
                'yahoo_refresh_token': user.yahoo_refresh_token,
                'yahoo_access_token': user.yahoo_access_token,
                'yahoo_update_time': user.yahoo_update_time,
                'yahoo_enable': user.yahoo_enable,
                'qoo10_username': user.qoo10_username,
                'qoo10_password': user.qoo10_password,
                'qoo10_store_name': user.qoo10_store_name,
                'qoo10_api_key': user.qoo10_api_key,
                'qoo10_sak': user.qoo10_sak,
                'qoo10_update_time': user.qoo10_update_time,
                'qoo10_enable': user.qoo10_enable,
            }
            status_code = status.HTTP_200_OK
            return Response(response, status=status_code)
        except Exception as e:
            print(str(e))

class UserRegisterView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        data = request.data
        user = User.objects.filter(
            Q(username=data['username'])).first()
        if user:
            status_code = status.HTTP_400_BAD_REQUEST
            response = {
                'success': 'False',
                'status code': status_code,
                'type': 'already',
            }
            return Response(response, status=status_code)
        else:
            try:
                user = User.objects.create_user(data['username'], "password")
                user.username = data['username']
                user.email = data['email']
                user.name = data['name']
                user.amazon_client_id = data['amazon_client_id']
                user.amazon_client_secret = data['amazon_client_secret']
                user.amazon_refresh_token = data['amazon_refresh_token']
                user.yahoo_store_id = data['yahoo_store_id']
                user.yahoo_store_name = data['yahoo_store_name']
                user.yahoo_client_id = data['yahoo_client_id']
                user.yahoo_client_secret = data['yahoo_client_secret']
                user.qoo10_username = data['qoo10_username']
                user.qoo10_password = data['qoo10_password']
                user.qoo10_store_name = data['qoo10_store_name']
                user.qoo10_api_key = data['qoo10_api_key']
                user.save()
                status_code = status.HTTP_200_OK
                response = {
                    'success': 'True',
                    'status code': status_code,
                }
                return Response(response, status=status_code)
            except Exception as e:
                print(str(e))
                status_code = status.HTTP_400_BAD_REQUEST
                response = {
                    'success': 'False',
                    'status code': status_code,
                    'type': 'system',
                }
                return Response(response, status=status_code)

    def put(self, request):
        data = request.data
        user = User.objects.filter(username=data['username']).first()
        user.email = data['email']
        user.name = data['name']
        user.amazon_client_id = data['amazon_client_id']
        user.amazon_client_secret = data['amazon_client_secret']
        user.amazon_refresh_token = data['amazon_refresh_token']
        user.yahoo_store_id = data['yahoo_store_id']
        user.yahoo_store_name = data['yahoo_store_name']
        user.yahoo_client_id = data['yahoo_client_id']
        user.yahoo_client_secret = data['yahoo_client_secret']
        user.qoo10_username = data['qoo10_username']
        user.qoo10_password = data['qoo10_password']
        user.qoo10_store_name = data['qoo10_store_name']
        user.qoo10_api_key = data['qoo10_api_key']
        user.save()
        status_code = status.HTTP_200_OK
        response = {
            'success': 'True',
            'status code': status_code,
        }
        return Response(response, status=status_code)

    def delete(self, request, user_id):
        user = User.objects.filter(user_id = request.data['user_id']).first()
        user.delete()
        return Response(True, status=status.HTTP_200_OK)


class UserUpdateView(APIView):
    permission_classes = (AllowAny,)
    def put(self, request, id):
        user = User.objects.filter(Q(id=id)).first()
        key = request.data['key']
        value = request.data['value']
        if(key=="qoo10_auto"):
            user.qoo10_auto = value
        else:
            user.yahoo_auto = value
        user.save()
        status_code = status.HTTP_200_OK
        response = {
            'status code': status.HTTP_200_OK
        }
        return Response(response, status=status_code)

class AllUsersView(APIView):
    permission_classes = (AllowAny, )

    def get(self, request):
        keyword = request.GET.get('keyword')
        if(keyword==""):
            allusers = User.objects.all().values('id','username', 'name', 'email', 'amazon_enable', 'yahoo_store_name', 'yahoo_store_id', 'yahoo_enable', 'qoo10_enable', 'qoo10_username', 'qoo10_store_name', 'yahoo_auto', 'qoo10_auto')
            for user in allusers:
                item = User.objects.filter(Q(id=user['id'])).first()
                item.seller_count = 2
                item.save()
        else:
            allusers = User.objects.filter(username__contains = keyword).values()
        return Response(allusers, status=status.HTTP_200_OK)
    
    
class AdminNgWordView(APIView):
    permission_classes = (AllowAny, )

    def get(self, request):

        m_setting = PushServiceGlobalSetting.objects.filter(name="default").first()

        if m_setting:
            ng_asin_codes = m_setting.ng_asin_codes
            ng_titles = m_setting.ng_titles
            ng_descriptions = m_setting.ng_descriptions
        else:
            ng_asin_codes = ""
            ng_titles = ""
            ng_descriptions = ""

        return Response({
            'ng_asin_codes': ng_asin_codes,
            'ng_titles': ng_titles,
            'ng_descriptions': ng_descriptions,
        }, status=status.HTTP_200_OK)
    
    def post(self, request):
        data = request.data
        
        m_setting = PushServiceGlobalSetting.objects.filter(name="default").first()
        if not m_setting:
            m_setting = PushServiceGlobalSetting.objects.create(name="default")

        m_setting.ng_asin_codes = data['ng_asin_codes']
        m_setting.ng_titles = data['ng_titles']
        m_setting.ng_descriptions = data['ng_descriptions']
        m_setting.save()

        return Response(True, status=status.HTTP_200_OK)
    

class PasswordView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        old_pwd = request.data['old_pwd']
        new_pwd = request.data['new_pwd']
        user = User.objects.filter(username=request.user.username).first()
        if user.check_password(old_pwd):
            user.set_password(new_pwd)
            user.save()
            return Response(None, status.HTTP_200_OK)
        else:
            return Response(None, status.HTTP_400_BAD_REQUEST)

class AmazonTokenView(APIView) :
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        user = request.user
        entrypoint = "https://api.amazon.com/auth/o2/token"
        client_id = user.amazon_client_id
        client_secret = user.amazon_client_secret
        refresh_token = user.amazon_refresh_token
        credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        header = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {credentials}"
        }
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token
        }
        response = requests.post(entrypoint, headers=header, data=data)
        print(response.json())
        access_token = response.json()["access_token"]
        time.sleep(0.3)
        db_user = User.objects.filter(username=user.username).first()
        db_user.amazon_access_token = access_token
        db_user.amazon_enable = True
        db_user.save()
        status_code = status.HTTP_200_OK
        response = {
            'success': True,
            'status code': status_code,
        }
        return Response(response, status=status_code)

class YahooTokenView(APIView) :
    permission_classes = (IsAuthenticated,)
    
    def post(self, request):
        user = request.user
        code = request.data['code']
        entrypoint = 'https://auth.login.yahoo.co.jp/yconnect/v2/token'
        data = {
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': 'https://pushservice.work/profile'
        }
        credentials = base64.b64encode(f"{user.yahoo_client_id}:{user.yahoo_client_secret}".encode()).decode()
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {credentials}"
        }

        response = requests.post(entrypoint, headers=headers, data=data)
        refresh_token = response.json()["refresh_token"]
        access_token = response.json()["access_token"]
        db_user = User.objects.filter(username=user.username).first()
        db_user.yahoo_refresh_token = refresh_token
        db_user.yahoo_access_token = access_token
        db_user.yahoo_enable = True
        db_user.save()
        
        status_code = status.HTTP_200_OK
        response = {
            'success': True,
            'status code': status_code,
        }
        return Response(response, status=status_code)

class Qoo10SAKView(APIView) :
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        user = request.user
        params = {
            'key': user.qoo10_api_key,
            'method': 'CertificationAPI.CreateCertificationKey',
            'user_id': user.qoo10_username,
            'pwd': user.qoo10_password,
        }
        response = requests.get('https://api.qoo10.jp/GMKT.INC.Front.QAPIService/ebayjapan.qapi', params)
        if response.json()["ResultMsg"] == "成功":
            sak = response.json()["ResultObject"]
            db_user = User.objects.filter(username=user.username).first()
            db_user.qoo10_sak = sak
            db_user.qoo10_enable = True
            db_user.save()
            return Response(None,status.HTTP_200_OK)
        else:
            return Response(None,status.HTTP_400_BAD_REQUEST)

class ExportProductView(APIView) :
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        user = request.user
        db_user = User.objects.filter(username=user.username).first()
        product = request.data['data']

        print(product['asin'] + " is been registering, please wait...")
            
        amzn_get_access_token_entrypoint = "https://api.amazon.com/auth/o2/token"
        amzn_marketplace_id = "A1VC38T7YXB528"
        amzn_client_id = db_user.amazon_client_id
        amzn_client_secret = db_user.amazon_client_secret
        amzn_access_token = db_user.amazon_access_token
        amzn_refresh_token = db_user.amazon_refresh_token
        amzn_grant_type = "refresh_token"       
        
        amzn_product_entrypoint = "https://sellingpartnerapi-fe.amazon.com/catalog/2022-04-01/items/"
        amzn_get_product_data_header = {
            "Authorization": "Bearer " + amzn_access_token,
            "Content-Type": "application/x-www-form-urlencoded",
            "x-amz-access-token": amzn_access_token,
        }
        response_amzn_product = requests.get(amzn_product_entrypoint+product['asin']+"?marketplaceIds="+amzn_marketplace_id+"&includedData=attributes,dimensions,identifiers,images,productTypes,salesRanks,summaries,relationships", headers=amzn_get_product_data_header)
        amzn_product_data_byte = response_amzn_product.content.decode().replace("'", '"')
        amzn_product_data_json = json.loads(amzn_product_data_byte)
        time.sleep(0.3)
        print(db_user.username, "Get amazon product data")
        try:
            if amzn_product_data_json['errors'][0]["code"] == "Unauthorized":
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
                    time.sleep(0.3)
                    db_user.amazon_access_token = amzn_access_token
                    db_user.save()
                    amzn_get_product_data_header = {
                        "Authorization": "Bearer " + amzn_access_token,
                        "Content-Type": "application/x-www-form-urlencoded",
                        "x-amz-access-token": amzn_access_token,
                    }
                    response_amzn_product = requests.get(amzn_product_entrypoint+product['asin']+"?marketplaceIds="+amzn_marketplace_id+"&includedData=attributes,dimensions,identifiers,images,productTypes,salesRanks,summaries,relationships", headers=amzn_get_product_data_header)
                    amzn_product_data_byte = response_amzn_product.content.decode().replace("'", '"')
                    amzn_product_data_json = json.loads(amzn_product_data_byte)
                    print("Get amazon product data")
                    time.sleep(0.3)
                except:
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

        # NG Word Test...
        ng_asin_codes = request.user.ng_asin_codes
        ng_asin_code_arr = [elem.strip(' ') for elem in ng_asin_codes.split('\n')]

        if PushServiceGlobalSetting.objects.filter(name="default").first():
            global_ng_asin_codes = PushServiceGlobalSetting.objects.filter(name="default").first().ng_asin_codes
            global_ng_asin_code_arr = [elem.strip(' ') for elem in global_ng_asin_codes.split('\n')]

            ng_asin_code_arr = ng_asin_code_arr + global_ng_asin_code_arr

        asin = product['asin']
        for ngword in ng_asin_code_arr:
            if(ngword == ""):
                continue
            if(ngword == asin):
                res_data = {
                    'err_type': 'NG_Word',
                    'success': False,
                }
                return Response(data=res_data, status=status.HTTP_400_BAD_REQUEST)

        product['name'] = amzn_product_data_json['summaries'][0]['itemName']
        
        if db_user.multi:
            relation = len(amzn_product_data_json['relationships'][0]['relationships'])
            if(relation!=0):
                res_data = {
                        'err_type': 'multi',
                        'success': False,
                    }
                return Response(data=res_data, status=status.HTTP_400_BAD_REQUEST)
        ng_titles = request.user.ng_titles
        ng_title_arr = [elem.strip(' ') for elem in ng_titles.split('\n')]

        if PushServiceGlobalSetting.objects.filter(name="default").first():
            global_ng_titles = PushServiceGlobalSetting.objects.filter(name="default").first().ng_titles
            global_ng_title_arr = [elem.strip(' ') for elem in global_ng_titles.split('\n')]

            ng_title_arr = ng_title_arr + global_ng_title_arr

        name = product['name']
        
        for ngword in ng_title_arr:
            if(ngword == ""):
                continue
            if(ngword in name):
                res_data = {
                    'err_type': 'NG_Word',
                    'success': False,
                }
                return Response(data=res_data, status=status.HTTP_400_BAD_REQUEST)
            
        product['description'] = ""
        try:
            features = amzn_product_data_json['attributes']['bullet_point']
            for feature in features:
                product['description'] += feature['value'] + ", "
            product['description'] = product['description'][:-2]
        except Exception as e:
            print("error_bullet_point", str(e))

        ng_descriptions = request.user.ng_descriptions
        ng_description_arr = [elem.strip(' ') for elem in ng_descriptions.split('\n')]

        if PushServiceGlobalSetting.objects.filter(name="default").first():
            global_ng_descriptions = PushServiceGlobalSetting.objects.filter(name="default").first().ng_descriptions
            global_ng_description_arr = [elem.strip(' ') for elem in global_ng_descriptions.split('\n')]

            ng_description_arr = ng_description_arr + global_ng_description_arr

        description = product['description']
        for ngword in ng_description_arr:
            if(ngword == ""):
                continue
            if(ngword in description):
                res_data = {
                    'err_type': 'NG_Word',
                    'success': False,
                }
                return Response(data=res_data, status=status.HTTP_400_BAD_REQUEST)

        try:
            product_weight = 0
            if amzn_product_data_json['dimensions'][0]['package']['weight']['unit'] == "pounds":
                product_weight = amzn_product_data_json['dimensions'][0]['package']['weight']['value'] / 2.20462
            else:
                product_weight = amzn_product_data_json['dimensions'][0]['package']['weight']['value']
            if product_weight > 50:
                res_data = {
                    'err_type': 'Size',
                    'success': False,
                }
                return Response(data=res_data, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(str(e))
        try:
            product_size_1 = 0
            product_size_2 = 0
            product_size_3 = 0
            if amzn_product_data_json['dimensions'][0]['package']['height']['unit'] == "inches":
                product_size_1 = amzn_product_data_json['dimensions'][0]['package']['height']['value'] * 2.54
            else:
                product_size_1 = amzn_product_data_json['dimensions'][0]['package']['height']['value']
            if amzn_product_data_json['dimensions'][0]['package']['height']['unit'] == "inches":
                product_size_2 = amzn_product_data_json['dimensions'][0]['package']['length']['value'] * 2.54
            else:
                product_size_2 = amzn_product_data_json['dimensions'][0]['package']['length']['value']
            if amzn_product_data_json['dimensions'][0]['package']['height']['unit'] == "inches":
                product_size_3 = amzn_product_data_json['dimensions'][0]['package']['width']['value'] * 2.54
            else:
                product_size_3 = amzn_product_data_json['dimensions'][0]['package']['width']['value']

            if product_size_1 > 160 or product_size_2 > 160 or product_size_3 > 160:
                res_data = {
                    'err_type': 'Size',
                    'success': False,
                }
                return Response(data=res_data, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(str(e))

        amzn_get_price_data_header = {
            "Authorization": "Bearer " + amzn_access_token,
            "Content-Type": "application/x-www-form-urlencoded",
            "x-amz-access-token": amzn_access_token,
        }
        amzn_price_entrypoint = "https://sellingpartnerapi-fe.amazon.com/products/pricing/v0/items/"
        response_amzn_price = requests.get(amzn_price_entrypoint+product['asin']+'/offers'+"?MarketplaceId="+amzn_marketplace_id+"&ItemCondition=New&CustomerType=Consumer", headers=amzn_get_price_data_header)
        print("Get amazon price data")
        amzn_price_data_byte = response_amzn_price.content.decode().replace("'", '"')
        amzn_price_data_json = json.loads(amzn_price_data_byte)
        if amzn_price_data_json['payload']['status'] == 'Success':
            product['stock'] = True
            sellers =len(amzn_price_data_json['payload']['Offers'])
            if(user.oneseller==True):
                if(sellers<=user.seller_count):
                    res_data = {
                        'err_type': 'Seller',
                        'detail': 'Seller Error',
                        'success': False,
                    }
                    return Response(data=res_data, status=status.HTTP_400_BAD_REQUEST)
        else:
            product['stock'] = False
            res_data = {
                'err_type': 'Remain',
                'detail': 'Price Error',
                'success': False,
            }
            return Response(data=res_data, status=status.HTTP_400_BAD_REQUEST)
        
        img_urls = product['img_urls']
        
        origin_price = 0
        shipping_fee = True
        try:
            for offer in amzn_price_data_json['payload']['Summary']['BuyBoxPrices']:
                if offer["condition"] == "New" and origin_price == 0:
                    if (int)(offer['Shipping']['Amount']) == 0:
                        shipping_fee = False
                        origin_price = (int)(offer['ListingPrice']['Amount'])
            if shipping_fee:
                res_data = {
                    'err_type': 'ShippingFee',
                    'detail': 'ShippingFee',
                    'success': False,
                }
                return Response(data=res_data, status=status.HTTP_400_BAD_REQUEST)
            print(origin_price, ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
        except Exception as e:
            print(str(e))
            res_data = {
                'err_type': 'Price',
                'detail': 'Price Error',
                'success': False,
            }
            return Response(data=res_data, status=status.HTTP_400_BAD_REQUEST)
        shipping_now = False
        for eligibleoffer in amzn_price_data_json['payload']['Summary']['BuyBoxEligibleOffers']:
                if eligibleoffer["fulfillmentChannel"] == "Amazon":
                    shipping_now = True
        if (origin_price < 1000 or origin_price > 30000) :
            res_data = {
                'err_type': 'Price',
                'detail': 'Price Error',
                'success': False,
            }
            return Response(data=res_data, status=status.HTTP_400_BAD_REQUEST)
        
        store_type = product['store_type']
        fee_record = Fee.objects.filter(Q(fee_user=request.user) & Q(price__gte=origin_price) & Q(store_type=store_type)).order_by('price').first()
        real_price = 0
        if fee_record:
            if(fee_record.fee_type):
                real_price = (int)((origin_price * fee_record.multi_rate / 100 + fee_record.ship_fee) + fee_record.fee)
            else:
                real_price = (int)((origin_price * fee_record.multi_rate / 100 + fee_record.ship_fee) * fee_record.fee / 100)
        else:
            res_data = {
                'err_type': 'Price',
                'detail': 'Price Error',
                'success': False,
            }
            return Response(data=res_data, status=status.HTTP_400_BAD_REQUEST)
        
        reg_store = ""
        if store_type == "Yahoo":
            reg_store = request.user.yahoo_store_id
        elif store_type == "Qoo10":
            reg_store = request.user.qoo10_store_name
        
        item_code = ""
        duplicate_product = Product.objects.filter(
            Q(product_user =request.user) & 
            Q(amznurl="https://www.amazon.co.jp/dp/" + product['asin'] + "?language=ja_JP") & 
            Q(store_type=store_type) &
            Q(store=reg_store)).first()
        if duplicate_product:
            item_code = duplicate_product.code
        if store_type == "Yahoo":
        # Yahoo API Work
            yahoo_client_id = db_user.yahoo_client_id
            yahoo_secret = db_user.yahoo_client_secret
            yahoo_refresh_token = db_user.yahoo_refresh_token
            yahoo_grant_type = "refresh_token"
            yahoo_access_token = db_user.yahoo_access_token
            yahoo_product_register_entrypoint = "https://circus.shopping.yahooapis.jp/ShoppingWebService/V1/editItem"
            yahoo_seller_id = db_user.yahoo_store_id
            yahoo_product_category = "44087"
            yahoo_image_register_entrypoint = 'https://circus.shopping.yahooapis.jp/ShoppingWebService/V1/uploadItemImage?seller_id=' + yahoo_seller_id
            yahoo_inventory_set_entrypoint = "https://circus.shopping.yahooapis.jp/ShoppingWebService/V1/setStock"
            real_path = (product['path'][:20]) if len(product['path']) > 20 else product['path']
            if len(real_path) == 20:
                if real_path[19] == ":":
                    real_path = real_path[:19]

            data_product = {
                'seller_id': yahoo_seller_id,
                'item_code': product['item_code'],
                'path': real_path,
                'name': (product['name'][:47] + '...') if len(product['name']) > 50 else product['name'],
                'product_category': yahoo_product_category,
                'original_price': origin_price if shipping_now else 0,
                'price': real_price if shipping_now else 0,
                'caption': (product['description'][:4997] + '...') if len(product['description']) > 5000 else product['description'],
                # 'abstract': (product['abstract'][:497] + '...') if len(product['abstract']) > 500 else product['abstract'],
                'explanation': (product['description'][:497] + '...') if len(product['description']) > 500 else product['description'],
            }
            data_inventory = {
                'seller_id': yahoo_seller_id,
                'item_code': product['item_code'],
                'quantity': "1" if shipping_now else "0",
            }

            yahoo_product_register_header = {
                    "Authorization": "Bearer " + yahoo_access_token,
                    "Content-Type": "application/x-www-form-urlencoded",
            }
            response = requests.post(yahoo_product_register_entrypoint, headers=yahoo_product_register_header, data=data_product)
            yahoo_response_data_byte = response.content.decode().replace("'", '"')
            if "xpired" in yahoo_response_data_byte:
                yahoo_get_access_token_entrypoint = "https://auth.login.yahoo.co.jp/yconnect/v2/token"
                yahoo_get_access_token_credentials = base64.b64encode(f"{yahoo_client_id}:{yahoo_secret}".encode()).decode()
                yahoo_get_access_token_headers = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": f"Basic {yahoo_get_access_token_credentials}"
                }
                yahoo_get_access_token_data = {
                    "grant_type": yahoo_grant_type,
                    "refresh_token": yahoo_refresh_token
                }
                try:
                    time.sleep(0.3)
                    response = requests.post(yahoo_get_access_token_entrypoint, headers=yahoo_get_access_token_headers, data=yahoo_get_access_token_data)
                    yahoo_access_token = response.json()["access_token"]
                    print(response)
                    db_user.yahoo_access_token = yahoo_access_token
                    db_user.save()
                    print("Get yahoo access token")
                    time.sleep(0.3)
                    yahoo_product_register_header = {
                            "Authorization": "Bearer " + yahoo_access_token,
                            "Content-Type": "application/x-www-form-urlencoded",
                    }
                    response = requests.post(yahoo_product_register_entrypoint, headers=yahoo_product_register_header, data=data_product)
                except:
                    db_user.yahoo_enable = False
                    db_user.save()
                    res_data = {
                        'err_type': 'API',
                        'success': False,
                    }
                    return Response(data=res_data, status=status.HTTP_400_BAD_REQUEST)
            print("Register yahoo product")
            time.sleep(0.3)
            db_user.yahoo_register_time = timezone.now()
            db_user.yahoo_update_time = timezone.now()
            db_user.save()
            yahoo_image_upload_header = {
                "Authorization": "Bearer " + yahoo_access_token
            }
            try:
                response = requests.post(yahoo_inventory_set_entrypoint, headers=yahoo_product_register_header, data=data_inventory)
                print("Add yahoo inventory amount")
                yahoo_response_data_byte = response.content.decode().replace("'", '"')
                time.sleep(0.3)
            except Exception:
                print(str(Exception))
            
            if duplicate_product:
                print("")
            else:
                try:
                    img_file = requests.get(img_urls[0])
                    img_files = {"file": (product['item_code'] +".jpg", img_file.content, "image/jpeg", {'Expires': '0'} )}
                    requests.post(yahoo_image_register_entrypoint, headers=yahoo_image_upload_header, files=img_files)
                    print("Upload yahoo product main image")
                    yahoo_response_data_byte = response.content.decode().replace("'", '"')
                    time.sleep(0.3)
                except Exception:
                    print(str(Exception))
                if(len(img_urls) > 1):
                    img_urls.pop(0)
                    for idx, img_url in enumerate(img_urls):
                        try:
                            img_file_src = requests.get(img_url)
                            real_idx = idx + 1
                            files = {"file": (product['item_code'] + "_" + str(real_idx) +".jpg", img_file_src.content, "image/jpeg", {'Expires': '0'} )}
                            requests.post(yahoo_image_register_entrypoint, headers=yahoo_image_upload_header, files=files)
                            print("Upload yahoo product main custom image", real_idx)
                            time.sleep(0.3)
                        except Exception:
                            print(str(Exception))
            print("reseving")
            yahoo_publish_reserve_entrypoint = "https://circus.shopping.yahooapis.jp/ShoppingWebService/V1/reservePublish"
            yahoo_yahoo_publish_reserve_header = {
                "Authorization": "Bearer " + yahoo_access_token,
                "Content-Type": "application/json"
            }
            resolve_data = {
                'seller_id': yahoo_seller_id,
                'mode':1
            }
            try:
                response = requests.post(yahoo_publish_reserve_entrypoint, headers=yahoo_yahoo_publish_reserve_header, data=resolve_data)
                print(response)
                print("reserved")
            except Exception:
                print("error while reserved")
                print(str(Exception))
        
        elif store_type == "Qoo10":
            db_user.qoo10_register_time = timezone.now()
            db_user.qoo10_update_time = timezone.now()
            db_user.save()
            if item_code == "":
                params = {
                    'key': user.qoo10_sak,
                    'v': '1.1',
                    'returnType': 'json',
                    'method': 'ItemsBasic.SetNewGoods',
                    'SecondSubCat': product['second_sub_cat'],
                    'OuterSecondSubCat': '',
                    'Drugtype': '',
                    'BrandNo': '',
                    'ItemTitle': (product['name'][:97] + '...') if len(product['name']) > 100 else product['name'],
                    'PromotionName': '',
                    'SellerCode': '',
                    'IndustrialCodeType': 'J',
                    'IndustrialCode': 'X' + product['asin'],
                    'ModelNM': '',
                    'ManufactureDate': '2000-01-01',
                    'ProductionPlaceType': '',
                    'ProductionPlace': '',
                    'Weight': '',
                    'Material': '',
                    'AdultYN': 'N',
                    'ContactInfo': '',
                    'StandardImage': img_urls[0],
                    'image_other_url': '',
                    'VideoURL': '',
                    'ItemDescription': '<html><body>' + product['description'] + '</body></html>',
                    'AdditionalOption': '',
                    'ItemType': '',
                    'option_info': '',
                    'RetailPrice': real_price if shipping_now else 0,
                    'ItemPrice': real_price if shipping_now else 0,
                    'ItemQty': 1 if shipping_now else 0,
                    'ExpireDate': '',
                    'ShippingNo': '',
                    'AvailableDateType': '0',
                    'AvailableDateValue': '3',
                    'Keyword': '',
                }
                response = requests.get('https://api.qoo10.jp/GMKT.INC.Front.QAPIService/ebayjapan.qapi', params)
                print(response.json())
                try:
                    if response.json()['ErrorMsg'] == "Invalid Access" or "存在しないAPIです。" :
                        db_user.qoo10_enable = False
                        db_user.save()
                        res_data = {
                            'err_type': 'API',
                            'success': False,
                        }
                        return Response(data=res_data, status=status.HTTP_400_BAD_REQUEST)
                except Exception as e:
                    print("")
                if response.json()["ResultCode"] != 0:
                    print(response.json())
                    return Response(None, status=status.HTTP_400_BAD_REQUEST)
                    
                time.sleep(0.3)
                item_code = response.json()['ResultObject']['GdNo']
                params = {
                    'key': user.qoo10_sak,
                    'v': '1.0',
                    'returnType': 'json',
                    'method': 'ItemsContents.EditGoodsMultiImage',
                    'ItemCode': item_code,
                }
                if(len(img_urls) > 1):
                    img_urls.pop(0)
                    for idx, img_url in enumerate(img_urls):
                        tmp_idx = idx + 1
                        tmp_key = 'EnlargedImage' + str(tmp_idx)
                        params[tmp_key] = img_urls[idx]
                response = requests.get('https://api.qoo10.jp/GMKT.INC.Front.QAPIService/ebayjapan.qapi', params)
                time.sleep(0.3)
            else:
                params = {
                    'key': user.qoo10_sak,
                    'v': '1.0',
                    'returnType': 'json',
                    'method': 'ItemsOrder.SetGoodsPriceQty',
                    'ItemCode': item_code,
                    'SellerCode': '',
                    'Price': (str)(real_price) if shipping_now else 0,
                    'TaxRate': '0',
                    'Qty': "1" if shipping_now else "0",
                    'ExpireDate': '',
                }
                response = requests.get('https://api.qoo10.jp/GMKT.INC.Front.QAPIService/ebayjapan.qapi', params)
                print(response.json())
                try:
                    if response.json()['ErrorMsg'] == "Invalid Access" or "存在しないAPIです。" :
                        db_user.qoo10_enable = False
                        db_user.save()
                        res_data = {
                            'err_type': 'API',
                            'success': False,
                        }
                        return Response(data=res_data, status=status.HTTP_400_BAD_REQUEST)
                except Exception as e:
                    print("")
                if response.json()["ResultCode"] != 0:
                    print(response)
                    return Response(None, status=status.HTTP_400_BAD_REQUEST)
                time.sleep(0.3)
                print("update success!")
        if duplicate_product:
            duplicate_product.price = real_price
            duplicate_product.created_at = timezone.now()
            duplicate_product.save()
            return Response({'detail': "Duplicate"}, status=status.HTTP_200_OK)
        Product.objects.create(
            product_user = request.user,
            amznurl = "https://www.amazon.co.jp/dp/" + product['asin'] + "?language=ja_JP",
            price = real_price if shipping_now else 0,
            store = reg_store,
            store_type = store_type,
            code = item_code,
            path=product['path'],
            second_sub_cat = product['second_sub_cat']
        )
        if shipping_now:
            return Response(True, status=status.HTTP_200_OK)
        else:
            res_data = {
                'err_type': 'Shipping',
                'detail': 'Shipping Error',
                'success': False,
            }
            return Response(data=res_data, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self, request):
        try:
            user = request.user
            active_store = request.data['active_store']
            product_idx = request.data['product_idx']
            bulk_cnt = request.data['bulk_cnt']
            
            sleep_time = 10
            products = Product.objects.filter(Q(product_user=user) & Q(store_type=active_store)).order_by('-created_at').values()
            db_amznurl_array = [item.get('amznurl') for item in products[product_idx:product_idx+bulk_cnt]]
            
            amzn_price_request_array = [
                {
                    "uri": "/products/pricing/v0/items/" + item[28:-15] + "/offers",
                    "method": "GET",
                    "MarketplaceId": "A1VC38T7YXB528",
                    "ItemCondition": "New",
                    "CustomerType": "Consumer"
                }
                        for item in db_amznurl_array]
            
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
            amzn_price_data_byte = response_amzn_price.content.decode().replace("'", '"')
            amzn_price_data_json = json.loads(amzn_price_data_byte)
            time.sleep(sleep_time)
            print("Get amazon price data")
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
                        amzn_price_data_byte = response_amzn_price.content.decode().replace("'", '"')
                        amzn_price_data_json = json.loads(amzn_price_data_byte)
                        time.sleep(sleep_time)
                        print("Get amazon price data again")
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

                        for offer in item['body']['payload']['Summary']['BuyBoxPrices']:
                            if offer["condition"] == "New" and lowest_price == 0:
                                lowest_price = (int)(offer['ListingPrice']['Amount'])

                        if lowest_price == 0:
                            qty = False
                        else:
                            qty = True if item['body']['payload']['status'] == 'Success' else False
                            
                        amzn_price_response_price_qty_array.append(
                            {
                                "qty": qty,
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
                    amzn_price_response_price_qty_array.append(
                        {
                            "qty": False,
                            "price": 0
                        }
                    )

            price_request_qty_array = ["1" if item['qty'] else "0" for item in amzn_price_response_price_qty_array]
            price_request_item_qty_string = ','.join(price_request_qty_array)
            price_request_price_array = [item['price'] for item in amzn_price_response_price_qty_array]

            real_price_array = []

            if active_store == "Yahoo":
                yahoo_client_id = db_user.yahoo_client_id
                yahoo_secret = db_user.yahoo_client_secret
                yahoo_refresh_token = db_user.yahoo_refresh_token
                yahoo_grant_type = "refresh_token"
                yahoo_access_token = db_user.yahoo_access_token
                yahoo_product_update_entrypoint = "https://circus.shopping.yahooapis.jp/ShoppingWebService/V1/updateItems"
                yahoo_seller_id = db_user.yahoo_store_id
                yahoo_inventory_set_entrypoint = "https://circus.shopping.yahooapis.jp/ShoppingWebService/V1/setStock"
                yahoo_price_request_item_code_array = ["X" + item[28:-15] for item in db_amznurl_array]
                yahoo_price_request_item_code_string = ','.join(yahoo_price_request_item_code_array)
                yahoo_price_request_data = {
                    'seller_id': yahoo_seller_id,
                }
                for idx, origin_price in enumerate(price_request_price_array):
                    fee_record = Fee.objects.filter(Q(fee_user=request.user) & Q(price__gte=origin_price) & Q(store_type=active_store)).order_by('price').first()
                    real_price = 0
                    if fee_record:
                        if(fee_record.fee_type):
                            real_price = (int)((origin_price * fee_record.multi_rate / 100 + fee_record.ship_fee) + fee_record.fee)
                        else:
                            real_price = (int)((origin_price * fee_record.multi_rate / 100 + fee_record.ship_fee) * fee_record.fee / 100)
                    
                        yahoo_price_request_data["item" + (str)(idx)] = "item_code=" + yahoo_price_request_item_code_array[idx] + "&original_price=" + (str)(origin_price) + "&price=" + (str)(real_price)
                    else:
                        yahoo_price_request_data["item" + (str)(idx)] = "item_code="


                    real_price_array.append(real_price)

                yahoo_product_update_header = {
                        "Authorization": "Bearer " + yahoo_access_token,
                        "Content-Type": "application/x-www-form-urlencoded",
                }
                response = requests.post(yahoo_product_update_entrypoint, headers=yahoo_product_update_header, data=yahoo_price_request_data)
                time.sleep(1)
                yahoo_response_data_byte = response.content.decode().replace("'", '"')
                if "xpired" in yahoo_response_data_byte:
                    yahoo_get_access_token_entrypoint = "https://auth.login.yahoo.co.jp/yconnect/v2/token"
                    yahoo_get_access_token_credentials = base64.b64encode(f"{yahoo_client_id}:{yahoo_secret}".encode()).decode()
                    yahoo_get_access_token_headers = {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Authorization": f"Basic {yahoo_get_access_token_credentials}"
                    }
                    yahoo_get_access_token_data = {
                        "grant_type": yahoo_grant_type,
                        "refresh_token": yahoo_refresh_token
                    }
                    try:
                        response = requests.post(yahoo_get_access_token_entrypoint, headers=yahoo_get_access_token_headers, data=yahoo_get_access_token_data)
                        time.sleep(1)
                        yahoo_access_token = response.json()["access_token"]
                        db_user.yahoo_access_token = yahoo_access_token
                        db_user.save()
                        print("Get yahoo access token")
                        yahoo_product_update_header = {
                                "Authorization": "Bearer " + yahoo_access_token,
                                "Content-Type": "application/x-www-form-urlencoded",
                        }
                        response = requests.post(yahoo_product_update_entrypoint, headers=yahoo_product_update_header, data=yahoo_price_request_data)
                        time.sleep(1)
                    except:
                        db_user.yahoo_enable = False
                        db_user.save()
                        res_data = {
                            'err_type': 'API',
                            'success': False,
                        }
                        return Response(data=res_data, status=status.HTTP_400_BAD_REQUEST)
                print("Register yahoo product")
                db_user.yahoo_update_time = timezone.now()
                db_user.save()

                data_inventory = {
                    'seller_id': yahoo_seller_id,
                    'item_code': yahoo_price_request_item_code_string,
                    'quantity': price_request_item_qty_string,
                }
                try:
                    response = requests.post(yahoo_inventory_set_entrypoint, headers=yahoo_product_update_header, data=data_inventory)
                    print("Update yahoo inventory amount")
                    time.sleep(1)
                except Exception as e:
                    print(str(e))
            elif active_store == "Qoo10":
                db_code_array = [item.get('code') for item in products[product_idx:product_idx+20]]
                ItemInfoJson = []
                for idx, origin_price in enumerate(price_request_price_array):
                    fee_record = Fee.objects.filter(Q(fee_user=request.user) & Q(price__gte=origin_price) & Q(store_type=active_store)).order_by('price').first()
                    real_price = 0
                    if fee_record:
                        if(fee_record.fee_type):
                            real_price = (int)((origin_price * fee_record.multi_rate / 100 + fee_record.ship_fee) + fee_record.fee)
                        else:
                            real_price = (int)((origin_price * fee_record.multi_rate / 100 + fee_record.ship_fee) * fee_record.fee / 100)
                        
                        ItemInfoJson.append({
                            'ItemCode': db_code_array[idx],
                            'SellerCode': '',
                            'Price': (str)(real_price),
                            'TaxRate': '0',
                            'Qty': "1" if amzn_price_response_price_qty_array[idx]['qty'] else "0",
                            'ExpireDate': '',
                        })
                    else:
                        ItemInfoJson.append({
                            'ItemCode': "",
                            'SellerCode': '',
                            'Price': "",
                            'TaxRate': '0',
                            'Qty': "0",
                            'ExpireDate': '',
                        })

                    real_price_array.append(real_price)

                params = {
                    'key': db_user.qoo10_sak,
                    'v': '1.0',
                    'returnType': 'json',
                    'method': 'ItemsOrder.SetGoodsPriceQtyBulk',
                    'ItemInfoJson': (str)(ItemInfoJson),
                }
                response = requests.get('https://api.qoo10.jp/GMKT.INC.Front.QAPIService/ebayjapan.qapi', params)
                try:
                    if response.json()['ErrorMsg'] == "Invalid Access" or "存在しないAPIです。" :
                        db_user.qoo10_enable = False
                        db_user.save()
                        res_data = {
                            'err_type': 'API',
                            'success': False,
                        }
                        return Response(data=res_data, status=status.HTTP_400_BAD_REQUEST)
                except Exception as e:
                    print("")
                time.sleep(1)
                db_user.qoo10_update_time = timezone.now()
                db_user.save()
            
            db_store_array = [item.get('store') for item in products[product_idx:product_idx+bulk_cnt]]
            for idx, tmp_amznurl in enumerate(db_amznurl_array):
                try:
                    find_product = Product.objects.filter(
                        Q(product_user =request.user) & 
                        Q(amznurl=tmp_amznurl) &
                        Q(store_type=active_store) &
                        Q(store=db_store_array[idx])
                        ).first()
                    find_product.qty = amzn_price_response_price_qty_array[idx]['qty']
                    find_product.price = real_price_array[idx]
                    find_product.save()
                except Exception as e:
                    print("")
            
            return Response(True, status=status.HTTP_200_OK)
        except Exception as e:
            print(str(e))
            return Response(False, status=status.HTTP_400_BAD_REQUEST)

class FeeView(APIView) :
    permission_classes = (IsAuthenticated,)

    def get(self, request, shop):
        user = request.user
        fee = Fee.objects.filter(Q(fee_user=user) & Q(store_type=shop)).order_by('price').values()
        
        status_code = status.HTTP_200_OK
        response = {
            'success': True,
            'status code': status_code,
            'fee': fee,
        }
        return Response(response, status=status_code)

    def post(self, request, shop):
        user = request.user
        data = request.data
        Fee.objects.create(
            fee_user = user,
            multi_rate = data['multirate'],
            ship_fee = data['ship_fee'],
            fee = data['fee'],
            price = data['price'],
            fee_type = data['fee_type'],
            store_type = shop,
        )
        
        status_code = status.HTTP_200_OK
        response = {
            'success': True,
            'status code': status_code,
        }
        return Response(response, status=status_code)
    
    def delete(self, request, shop):
        data = request.data
        item = Fee.objects.filter(id=data['id']).first()
        item.delete()
        
        status_code = status.HTTP_200_OK
        response = {
            'success': True,
            'status code': status_code,
        }
        return Response(response, status=status_code)
        

class NGWordView(APIView) :
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        user = request.user        
        status_code = status.HTTP_200_OK
        response = {
            'success': True,
            'status code': status_code,
            'ng_asin_codes': user.ng_asin_codes,
            'ng_titles': user.ng_titles,
            'ng_descriptions': user.ng_descriptions,
            'oneseller': user.oneseller,
            'seller_count':user.seller_count,
            'multi':user.multi,
            'yahoo_auto':user.yahoo_auto,
            'qoo10_auto':user.qoo10_auto,
            'id':user.id
        }
        return Response(response, status=status_code)

    def post(self, request):
        user = request.user
        user.ng_asin_codes = request.data['ng_asin_codes']
        user.ng_titles = request.data['ng_titles']
        user.ng_descriptions = request.data['ng_descriptions']
        user.oneseller = request.data['oneseller']
        user.seller_count = request.data['seller_count']
        user.multi = request.data['multi']
        user.save()
        
        status_code = status.HTTP_200_OK
        response = {
            'success': True,
            'status code': status_code,
        }
        return Response(response, status=status_code)
    
    
class NGAsinView(APIView) :
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        data = dict(request.data)
        asin = data.get('asin', '')
        
        try:
            user = request.user
            user.ng_asin_codes = user.ng_asin_codes + '\n' + asin
            user.save()

            status_code = status.HTTP_200_OK
            response = {
                'success': True,
                'status code': status_code,
            }
            return Response(response, status=status_code)
        except Exception as e:
            print(str(e))
            return Response(False, status=status.HTTP_400_BAD_REQUEST)

class ProductView(APIView) :
    permission_classes = (IsAuthenticated,)

    def get(self, request, shop):
        user = request.user
        products = Product.objects.filter(Q(product_user=user) & Q(store_type=shop)).order_by('-created_at').values()
        
        status_code = status.HTTP_200_OK
        response = {
            'success': True,
            'status code': status_code,
            'products': products,
            'yahoo_update_time': user.yahoo_update_time,
            'qoo10_update_time':user.qoo10_update_time
        }
        return Response(response, status=status_code)
    

    def delete(self, request, shop):
        try:
            user = request.user
            
            # with transaction.atomic():
            m_product = Product.objects.get(id=shop, product_user=user)

            if m_product.store_type == "Yahoo":
                yahoo_client_id = user.yahoo_client_id
                yahoo_secret = user.yahoo_client_secret
                yahoo_refresh_token = user.yahoo_refresh_token
                yahoo_grant_type = "refresh_token"
                yahoo_access_token = user.yahoo_access_token
                yahoo_product_delete_entrypoint = "https://circus.shopping.yahooapis.jp/ShoppingWebService/V1/deleteItem"

                item_code = "X" + m_product.amznurl.replace("https://www.amazon.co.jp/dp/", "").replace("?language=ja_JP", "")

                data = {
                    'seller_id': user.yahoo_store_id,
                    'item_code': item_code,
                }

                yahoo_product_delete_header = {
                    "Authorization": "Bearer " + yahoo_access_token,
                    "Content-Type": "application/x-www-form-urlencoded",
                }

                response = requests.post(yahoo_product_delete_entrypoint, headers=yahoo_product_delete_header, data=data)

                if "xpired" in response.content.decode().replace("'", '"'):
                    yahoo_get_access_token_entrypoint = "https://auth.login.yahoo.co.jp/yconnect/v2/token"
                    yahoo_get_access_token_credentials = base64.b64encode(f"{yahoo_client_id}:{yahoo_secret}".encode()).decode()
                    yahoo_get_access_token_headers = {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Authorization": f"Basic {yahoo_get_access_token_credentials}"
                    }
                    yahoo_get_access_token_data = {
                        "grant_type": yahoo_grant_type,
                        "refresh_token": yahoo_refresh_token
                    }
                    try:
                        response = requests.post(yahoo_get_access_token_entrypoint, headers=yahoo_get_access_token_headers, data=yahoo_get_access_token_data)
                        yahoo_access_token = response.json()["access_token"]
                        user.yahoo_access_token = yahoo_access_token
                        user.save()
                        print("Get yahoo access token")
                        yahoo_product_delete_header = {
                                "Authorization": "Bearer " + yahoo_access_token,
                                "Content-Type": "application/x-www-form-urlencoded",
                        }
                        response = requests.post(yahoo_product_delete_entrypoint, headers=yahoo_product_delete_header, data=data)
                    except:
                        user.yahoo_enable = False
                        user.save()
                        # res_data = {
                        #     'err_type': 'API',
                        #     'success': False,
                        # }
                        # return Response(data=res_data, status=status.HTTP_400_BAD_REQUEST)

                time.sleep(0.3)
                print("Delete yahoo product", response.status_code)

            elif m_product.store_type == "Qoo10":
                params = {
                    'key': user.qoo10_sak,
                    'v': '1.0',
                    'returnType': 'json',
                    'method': 'ItemsBasic.EditGoodsStatus',
                    'ItemCode': m_product.code,
                    'SellerCode': "",
                    'Status': "3"
                }
                response = requests.get('https://api.qoo10.jp/GMKT.INC.Front.QAPIService/ebayjapan.qapi', params)

                print(response.status_code)
                # if response.status_code != 200:
                #     return Response(None, status=status.HTTP_400_BAD_REQUEST)

                time.sleep(0.3)
                print("Delete qoo10 product", response.status_code)
            try:
                m_product.delete()
            except Exception as e:
                print(str(e))

            # return Response({
            #     "success": True,
            # }, status=200)
        
        except Exception as e:
            print(str(e))
            return Response({
                "msg": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

class AllNotificationsView(APIView) :
    permission_classes = (AllowAny, )

    def get(self, request):
        allnotifications = Notification.objects.all().order_by('-created_at').values()
        return Response(allnotifications, status=status.HTTP_200_OK)
    
    def post(self, request):

        Notification.objects.create(
            created_at = request.data['created_at'],
            title = request.data['title'],
            content = request.data['content'],
            url = request.data['url'],
        )
        return Response(True, status=status.HTTP_200_OK)
    
class NotificationHandleView(APIView) :
    permission_classes = (AllowAny, )
    
    def get(self, request, item_id):
        item = Notification.objects.filter(id=item_id).first()
        response = {
            'created_at': item.created_at,
            'title': item.title,
            'content': item.content,
            'url': item.url,
        }
        return Response(response, status=status.HTTP_200_OK)
    
    def post(self, request, item_id):
        item = Notification.objects.filter(id=item_id).first()
        item.created_at = request.data['created_at']
        item.title = request.data['title']
        item.content = request.data['content']
        item.url = request.data['url']
        item.save()
        print("here")
        return Response(True, status=status.HTTP_200_OK)

    def delete(self, request, item_id):
        item = Notification.objects.filter(id=item_id).first()
        item.delete()
        return Response(True, status=status.HTTP_200_OK)
    

class AutoUdateView(APIView):
    permission_classes = (AllowAny, )
    def post(self, request, id):        
        user = User.objects.filter(id=id).first()
        active_store = request.data['active_store']
        products = Product.objects.filter(Q(product_user=user) & Q(store_type=active_store)).order_by('created_at').values()
        for product in products:
            try:
                item = Product.objects.filter(Q(id = product['id'])).first()
                print("active store", active_store)
                if active_store == "Yahoo":
                    print("deleting yahoo")
                    yahoo_client_id = user.yahoo_client_id
                    yahoo_secret = user.yahoo_client_secret
                    yahoo_refresh_token = user.yahoo_refresh_token
                    yahoo_grant_type = "refresh_token"
                    yahoo_access_token = user.yahoo_access_token
                    yahoo_product_delete_entrypoint = "https://circus.shopping.yahooapis.jp/ShoppingWebService/V1/deleteItem"
                    item_code = "X" + item.amznurl.replace("https://www.amazon.co.jp/dp/", "").replace("?language=ja_JP", "")
                    data = {
                        'seller_id': user.yahoo_store_id,
                        'item_code': item_code,
                    }
                    yahoo_product_delete_header = {
                        "Authorization": "Bearer " + yahoo_access_token,
                        "Content-Type": "application/x-www-form-urlencoded",
                    }
                    response = requests.post(yahoo_product_delete_entrypoint, headers=yahoo_product_delete_header, data=data)
                    if "xpired" in response.content.decode().replace("'", '"'):
                        yahoo_get_access_token_entrypoint = "https://auth.login.yahoo.co.jp/yconnect/v2/token"
                        yahoo_get_access_token_credentials = base64.b64encode(f"{yahoo_client_id}:{yahoo_secret}".encode()).decode()
                        yahoo_get_access_token_headers = {
                            "Content-Type": "application/x-www-form-urlencoded",
                            "Authorization": f"Basic {yahoo_get_access_token_credentials}"
                        }
                        yahoo_get_access_token_data = {
                            "grant_type": yahoo_grant_type,
                            "refresh_token": yahoo_refresh_token
                        }
                        try:
                            response = requests.post(yahoo_get_access_token_entrypoint, headers=yahoo_get_access_token_headers, data=yahoo_get_access_token_data)
                            yahoo_access_token = response.json()["access_token"]
                            user.yahoo_access_token = yahoo_access_token
                            user.save()
                            print("Get yahoo access token for update")
                            yahoo_product_delete_header = {
                                    "Authorization": "Bearer " + yahoo_access_token,
                                    "Content-Type": "application/x-www-form-urlencoded",
                            }
                            response = requests.post(yahoo_product_delete_entrypoint, headers=yahoo_product_delete_header, data=data)
                        except:
                            user.yahoo_enable = False
                            user.save()
                            return Response(False, status=status.HTTP_400_BAD_REQUEST)
                else:
                    print("deleting Qoo10")
                    params = {
                        'key': user.qoo10_sak,
                        'v': '1.0',
                        'returnType': 'json',
                        'method': 'ItemsBasic.EditGoodsStatus',
                        'ItemCode': item.code,
                        'SellerCode': "",
                        'Status': "3"
                    }
                    response = requests.get('https://api.qoo10.jp/GMKT.INC.Front.QAPIService/ebayjapan.qapi', params)
                time.sleep(0.3)
                amzn_get_access_token_entrypoint = "https://api.amazon.com/auth/o2/token"
                amzn_marketplace_id = "A1VC38T7YXB528"
                amzn_client_id = user.amazon_client_id
                amzn_client_secret = user.amazon_client_secret
                amzn_access_token = user.amazon_access_token
                amzn_refresh_token = user.amazon_refresh_token
                amzn_grant_type = "refresh_token"       
                
                amzn_product_entrypoint = "https://sellingpartnerapi-fe.amazon.com/catalog/2022-04-01/items/"
                amzn_get_product_data_header = {
                    "Authorization": "Bearer " + amzn_access_token,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "x-amz-access-token": amzn_access_token,
                }
                product = {}
                product['asin'] = item.amznurl[28:-15]
                product['item_code'] = 'X' + product['asin']
                product['name'] = ""
                response_amzn_product = requests.get(amzn_product_entrypoint+ product['asin'] +"?marketplaceIds="+amzn_marketplace_id+"&includedData=attributes,dimensions,identifiers,images,productTypes,salesRanks,summaries,relationships", headers=amzn_get_product_data_header)
                amzn_product_data_byte = response_amzn_product.content.decode().replace("'", '"')
                amzn_product_data_json = json.loads(amzn_product_data_byte)
                time.sleep(0.3)
                print("Get amazon product data for update")
                deleted = False
                try:
                    if amzn_product_data_json['errors'][0]["code"] == "Unauthorized":
                        print(amzn_product_data_json['errors'][0]["code"])
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
                            
                            print("Getting amazon access token for updating")
                            amzn_get_access_token_response = requests.post(amzn_get_access_token_entrypoint, headers=amzn_get_access_token_header, data=amzn_get_access_token_data)
                            amzn_access_token = amzn_get_access_token_response.json()["access_token"]
                            print("Get amazon access token for updating")
                            time.sleep(0.3)
                            user.amazon_access_token = amzn_access_token
                            user.save()
                            amzn_get_product_data_header = {
                                "Authorization": "Bearer " + amzn_access_token,
                                "Content-Type": "application/x-www-form-urlencoded",
                                "x-amz-access-token": amzn_access_token,
                            }
                            print(user.username, "Geting amazon product data for update")
                            response_amzn_product = requests.get(amzn_product_entrypoint + product['asin'] + "?marketplaceIds="+amzn_marketplace_id+"&includedData=attributes,dimensions,identifiers,images,productTypes,salesRanks,summaries,relationships", headers=amzn_get_product_data_header)
                            amzn_product_data_byte = response_amzn_product.content.decode().replace("'", '"')
                            amzn_product_data_json = json.loads(amzn_product_data_byte)
                            print(user.username, "Geted amazon product data for update")
                            time.sleep(1)
                        except:
                            print('amazon app error for updating')
                            user.amazon_enable = False
                            user.save()
                            res_data = {
                                'err_type': 'API',
                                'detail': 'Amazon',
                                'success': False,
                            }
                            return Response(data=res_data, status=status.HTTP_400_BAD_REQUEST)
                except Exception as e:
                    print("OK")

                # NG Word Test...
                ng_asin_codes = user.ng_asin_codes
                ng_asin_code_arr = [elem.strip(' ') for elem in ng_asin_codes.split('\n')]

                if PushServiceGlobalSetting.objects.filter(name="default").first():
                    global_ng_asin_codes = PushServiceGlobalSetting.objects.filter(name="default").first().ng_asin_codes
                    global_ng_asin_code_arr = [elem.strip(' ') for elem in global_ng_asin_codes.split('\n')]
                    ng_asin_code_arr = ng_asin_code_arr + global_ng_asin_code_arr
                
                for ngword in ng_asin_code_arr:
                    if(ngword == ""):
                        continue
                    if(ngword == product['asin']):
                        item.delete()
                        deleted = True
                        break
                if deleted:
                    continue

                product['name'] = amzn_product_data_json['summaries'][0]['itemName']
                if user.multi:
                    relation = len(amzn_product_data_json['relationships'][0]['relationships'])
                    if(relation!=0):
                        item.delete()
                        continue
                ng_titles = user.ng_titles
                ng_title_arr = [elem.strip(' ') for elem in ng_titles.split('\n')]

                if PushServiceGlobalSetting.objects.filter(name="default").first():
                    global_ng_titles = PushServiceGlobalSetting.objects.filter(name="default").first().ng_titles
                    global_ng_title_arr = [elem.strip(' ') for elem in global_ng_titles.split('\n')]
                    ng_title_arr = ng_title_arr + global_ng_title_arr

                name = product['name']
                
                for ngword in ng_title_arr:
                    if(ngword == ""):
                        continue
                    if(ngword in name):
                        item.delete()
                        deleted = True
                        break
                if deleted:
                    continue

                product['description'] = ""
                try:
                    features = amzn_product_data_json['attributes']['bullet_point']
                    for feature in features:
                        product['description'] += feature['value'] + ", "
                    product['description'] = product['description'][:-2]
                except Exception as e:
                    print("error_bullet_point",str(e))

                ng_descriptions = user.ng_descriptions
                ng_description_arr = [elem.strip(' ') for elem in ng_descriptions.split('\n')]

                if PushServiceGlobalSetting.objects.filter(name="default").first():
                    global_ng_descriptions = PushServiceGlobalSetting.objects.filter(name="default").first().ng_descriptions
                    global_ng_description_arr = [elem.strip(' ') for elem in global_ng_descriptions.split('\n')]

                    ng_description_arr = ng_description_arr + global_ng_description_arr

                description = product['description']
                for ngword in ng_description_arr:
                    if(ngword == ""):
                        continue
                    if(ngword in description):
                        deleted = True
                        item.delete()
                        break
                if deleted:
                    continue
                try:
                    product_weight = 0
                    if amzn_product_data_json['dimensions'][0]['package']['weight']['unit'] == "pounds":
                        product_weight = amzn_product_data_json['dimensions'][0]['package']['weight']['value'] / 2.20462
                    else:
                        product_weight = amzn_product_data_json['dimensions'][0]['package']['weight']['value']
                    if product_weight > 50:
                        item.delete()
                        continue

                except Exception as e:
                    print(str(e))
                
                amzn_get_price_data_header = {
                    "Authorization": "Bearer " + amzn_access_token,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "x-amz-access-token": amzn_access_token,
                }
                amzn_price_entrypoint = "https://sellingpartnerapi-fe.amazon.com/products/pricing/v0/items/"
                response_amzn_price = requests.get(amzn_price_entrypoint+product['asin']+'/offers'+"?MarketplaceId="+amzn_marketplace_id+"&ItemCondition=New&CustomerType=Consumer", headers=amzn_get_price_data_header)
                print("Get amazon price data")
                amzn_price_data_byte = response_amzn_price.content.decode().replace("'", '"')
                amzn_price_data_json = json.loads(amzn_price_data_byte)
                if amzn_price_data_json['payload']['status'] == 'Success':
                    product['stock'] = True
                    sellers =len(amzn_price_data_json['payload']['Offers'])
                    if(user.oneseller==True):
                        if(sellers<=user.seller_count):
                            item.delete()
                            continue
                else:
                    item.delete()
                    continue
                product['img_urls'] =  [images.get('link') for images in amzn_product_data_json['images'][0]['images']][:5]                
                origin_price = 0
                try:
                    for offer in amzn_price_data_json['payload']['Summary']['BuyBoxPrices']:
                        if offer["condition"] == "New" and origin_price == 0:
                            origin_price = (int)(offer['ListingPrice']['Amount'])

                except Exception as e:
                    item.delete()
                    continue
                if (origin_price < 1000 or origin_price > 30000) :
                    item.delete()
                    continue
                
                store_type = item.store_type
                fee_record = Fee.objects.filter(Q(fee_user=user) & Q(price__gte=origin_price) & Q(store_type=store_type)).order_by('price').first()
                real_price = 0
                if fee_record:
                    if(fee_record.fee_type):
                        real_price = (int)((origin_price * fee_record.multi_rate / 100 + fee_record.ship_fee) + fee_record.fee)
                    else:
                        real_price = (int)((origin_price * fee_record.multi_rate / 100 + fee_record.ship_fee) * fee_record.fee / 100)
                else:
                    item.delete()
                    continue
                item.price = real_price
                item.save()
                print("registering Yahoo11")
                time.sleep(0.3)
                if active_store == "Yahoo":
                    print("registering entrypoint")
                    user.yahoo_update_time = timezone.now()
                    user.save()
                    yahoo_client_id = user.yahoo_client_id
                    yahoo_secret = user.yahoo_client_secret
                    yahoo_refresh_token = user.yahoo_refresh_token
                    yahoo_grant_type = "refresh_token"
                    yahoo_access_token = user.yahoo_access_token
                    yahoo_product_register_entrypoint = "https://circus.shopping.yahooapis.jp/ShoppingWebService/V1/editItem"
                    yahoo_seller_id = user.yahoo_store_id
                    yahoo_product_category = "44087"
                    yahoo_image_register_entrypoint = 'https://circus.shopping.yahooapis.jp/ShoppingWebService/V1/uploadItemImage?seller_id=' + yahoo_seller_id
                    yahoo_inventory_set_entrypoint = "https://circus.shopping.yahooapis.jp/ShoppingWebService/V1/setStock"
                    real_path =  (item.path[:20]) if len(item.path) > 20 else item.path
                    if len(real_path) == 20:
                        if real_path[19] == ":":
                            real_path = real_path[:19]
                    data_product = {
                        'seller_id': yahoo_seller_id,
                        'item_code': product['item_code'],
                        'path': real_path,
                        'name': (product['name'][:47] + '...') if len(product['name']) > 50 else product['name'],
                        'product_category': yahoo_product_category,
                        'original_price': origin_price,
                        'price': real_price,
                        'caption': (product['description'][:4997] + '...') if len(product['description']) > 5000 else product['description'],
                        # 'abstract': (product['abstract'][:497] + '...') if len(product['abstract']) > 500 else product['abstract'],
                        'explanation': (product['description'][:497] + '...') if len(product['description']) > 500 else product['description'],
                    }
                    data_inventory = {
                        'seller_id': yahoo_seller_id,
                        'item_code': product['item_code'],
                        'quantity': "1" if product['stock'] else "0",
                    }

                    yahoo_product_register_header = {
                            "Authorization": "Bearer " + yahoo_access_token,
                            "Content-Type": "application/x-www-form-urlencoded",
                    }
                    print("registering entrypoint")
                    response = requests.post(yahoo_product_register_entrypoint, headers=yahoo_product_register_header, data=data_product)
                    time.sleep(0.3)
                    yahoo_image_upload_header = {
                        "Authorization": "Bearer " + yahoo_access_token
                    }
                    try:
                        response = requests.post(yahoo_inventory_set_entrypoint, headers=yahoo_product_register_header, data=data_inventory)                   
                        time.sleep(0.3)
                    except Exception:
                        print("error while updating yahoo inventory amount", str(Exception))
                    img_urls = product['img_urls']
                    print(img_urls)
                    try:
                        img_file = requests.get(img_urls[0])
                        img_files = {"file": (product['item_code'] +".jpg", img_file.content, "image/jpeg", {'Expires': '0'} )}
                        requests.post(yahoo_image_register_entrypoint, headers=yahoo_image_upload_header, files=img_files)
                        time.sleep(0.3)
                    except Exception:
                        print(str(Exception))
                    if(len(img_urls) > 1):
                        img_urls.pop(0)
                        for idx, img_url in enumerate(img_urls):
                            try:
                                print(img_urls)
                                img_file_src = requests.get(img_url)
                                real_idx = idx + 1
                                files = {"file": (product['item_code'] + "_" + str(real_idx) +".jpg", img_file_src.content, "image/jpeg", {'Expires': '0'} )}
                                requests.post(yahoo_image_register_entrypoint, headers=yahoo_image_upload_header, files=files)
                                time.sleep(0.3)
                            except Exception:
                                print("error while update image",str(Exception))

                    print("reseving")
                    yahoo_publish_reserve_entrypoint = "https://circus.shopping.yahooapis.jp/ShoppingWebService/V1/reservePublish"
                    yahoo_yahoo_publish_reserve_header = {
                        "Authorization": "Bearer " + yahoo_access_token,
                        "Content-Type": "application/json"
                    }
                    resolve_data = {
                        'seller_id': yahoo_seller_id,
                        'mode':1
                    }
                    try:
                        response = requests.post(yahoo_publish_reserve_entrypoint, headers=yahoo_yahoo_publish_reserve_header, data=resolve_data)
                        print(response)
                        print("reserved")
                    except Exception:
                        print("error while reserved")
                        print(str(Exception))

                    item.created_at = timezone.now()
                    item.save()
                    print("updated")
                else:
                    print("registering Qoo")
                    user.qoo10_update_time = timezone.now()
                    user.save()
                    img_urls = product['img_urls']
                    params = {
                        'key': user.qoo10_sak,
                        'v': '1.1',
                        'returnType': 'json',
                        'method': 'ItemsBasic.SetNewGoods',
                        'SecondSubCat': item.second_sub_cat,
                        'OuterSecondSubCat': '',
                        'Drugtype': '',
                        'BrandNo': '',
                        'ItemTitle': (product['name'][:97] + '...') if len(product['name']) > 100 else product['name'],
                        'PromotionName': '',
                        'SellerCode': '',
                        'IndustrialCodeType': 'J',
                        'IndustrialCode': 'X' + product['asin'],
                        'ModelNM': '',
                        'ManufactureDate': '2000-01-01',
                        'ProductionPlaceType': '',
                        'ProductionPlace': '',
                        'Weight': '',
                        'Material': '',
                        'AdultYN': 'N',
                        'ContactInfo': '',
                        'StandardImage': img_urls[0],
                        'image_other_url': '',
                        'VideoURL': '',
                        'ItemDescription': '<html><body>' + product['description'] + '</body></html>',
                        'AdditionalOption': '',
                        'ItemType': '',
                        'option_info': '',
                        'RetailPrice': real_price,
                        'ItemPrice': real_price,
                        'ItemQty': 1 if product['stock'] else 0,
                        'ExpireDate': '',
                        'ShippingNo': '',
                        'AvailableDateType': '0',
                        'AvailableDateValue': '3',
                        'Keyword': '',
                    }
                    response = requests.get('https://api.qoo10.jp/GMKT.INC.Front.QAPIService/ebayjapan.qapi', params)
                    print(response.json())
                    try:
                        if response.json()['ErrorMsg'] == "Invalid Access" or "存在しないAPIです。" :
                            user.qoo10_enable = False
                            user.save()
                            continue
                    except Exception as e:
                        print("")
                    if response.json()["ResultCode"] != 0:
                        continue
                        
                        
                    time.sleep(0.3)
                    item_code = response.json()['ResultObject']['GdNo']
                    params = {
                        'key': user.qoo10_sak,
                        'v': '1.0',
                        'returnType': 'json',
                        'method': 'ItemsContents.EditGoodsMultiImage',
                        'ItemCode': item_code,
                    }
                    item.code = item_code
                    item.created_at = timezone.now()
                    item.save()
                    if(len(img_urls) > 1):
                        img_urls.pop(0)
                        for idx, img_url in enumerate(img_urls):
                            tmp_idx = idx + 1
                            tmp_key = 'EnlargedImage' + str(tmp_idx)
                            params[tmp_key] = img_urls[idx]
                    response = requests.get('https://api.qoo10.jp/GMKT.INC.Front.QAPIService/ebayjapan.qapi', params)
            except Exception as e:
                print("total", str(e))
        return Response(True, status=status.HTTP_200_OK)