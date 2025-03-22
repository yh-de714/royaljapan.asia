from rest_framework import status
from rest_framework.generics import CreateAPIView, RetrieveAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from royal.api.serializers import UserLoginSerializer, AdminLoginSerializer
from royal.api.models import *
from django.db import transaction
from random import randint
from django.db.models import Q
import stripe
import os
from django.core.files.storage import FileSystemStorage
from django.core.mail import EmailMultiAlternatives
import simplejson as json
from email.mime.image import MIMEImage
from django.conf import settings
stripe.api_key = "sk_test_51PvaMkKQfMI1g1n8r2k48hStNnoJWfl8YQ4Q5J38SKXvImqJ0GScGxfrcHl1TreQ83ndlPJBfsOyzYrYukGeywhl00R9G7TaAC"

# from django.db import connection
from rest_framework.views import APIView

class UserLoginView(RetrieveAPIView):
    permission_classes = (AllowAny,)
    serializer_class = UserLoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        response = {
            'status code': status.HTTP_200_OK,
            'token': serializer.data['token'],
            'refresh': serializer.data['refresh']
        }
        status_code = status.HTTP_200_OK
        return Response(response, status=status_code)

class AdminLoginView(RetrieveAPIView):
    permission_classes = (AllowAny,)
    serializer_class = AdminLoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        response = {
            'status code': status.HTTP_200_OK,
            'token': serializer.data['token'],
            'refresh': serializer.data['refresh']
        }
        status_code = status.HTTP_200_OK
        return Response(response, status=status_code)

class UserRegisterView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        data = request.data
        user = User.objects.filter(
            Q(email=data['email'])).first()
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
                user = User.objects.create_user(data['email'], data['password'])
                user.email = data['email']
                user.username = data['name']
                user.save()
                products = stripe.Product.list(limit=10000)
                for product in products:
                    price = stripe.Price.retrieve(product.default_price)
                    Product.objects.create(
                        seller = user,
                        description = product.description,
                        image = product.images[0],
                        title = product.name,
                        price_origin = price.unit_amount,
                        price_sell = price.unit_amount,
                        price_id = product.default_price,
                        product_id = product.id
                    )

                code = random_with_N_digits(8)
                Coupon.objects.create(
                    user = user,
                    code = code,
                    percent = 10
                )
                code = random_with_N_digits(8)
                Coupon.objects.create(
                    user = user,
                    code = code,
                    percent = 15
                )
                code = random_with_N_digits(8)
                Coupon.objects.create(
                    user = user,
                    code = code,
                    percent = 20
                )
                code = random_with_N_digits(8)
                Coupon.objects.create(
                    user = user,
                    code = code,
                    percent = 25
                )
                code = random_with_N_digits(8)
                Coupon.objects.create(
                    user = user,
                    code = code,
                    percent = 30
                )
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


class GetMyDataView(APIView):
    permission_classes = (IsAuthenticated,)
    def get(self, request):
        user = request.user
        products = Product.objects.filter(Q(seller = user)).values()
        coupons = Coupon.objects.filter(Q(user = user)).values()
        response = {
            'status code': status.HTTP_200_OK,
            'id':user.id,
            'name':user.username,
            'products':products,
            'coupons':coupons
        }
        status_code = status.HTTP_200_OK
        return Response(response, status=status_code)
    
class UserView(APIView):
    permission_classes = (IsAuthenticated,)
    def get(self, request, id):
        request_user = request.user
        if request_user.is_superuser:
            user = User.objects.filter(Q(id=id)).first()
            products = Product.objects.filter(Q(seller = user)).values()
            coupons = Coupon.objects.filter(Q(user = user)).values()
            response = {
                'status code': status.HTTP_200_OK,
                'id':user.id,
                'email':user.email,
                'name':user.username,
                'products':products,
                'coupons':coupons
            }
            status_code = status.HTTP_200_OK
            return Response(response, status=status_code)
        else:
            response = {
                'status code': status.HTTP_401_UNAUTHORIZED,
            }
            status_code = status.HTTP_401_UNAUTHORIZED
            return Response(response, status=status_code)
       

class GetUserDataView(APIView):
    permission_classes = (IsAuthenticated,)
    def get(self, request):
        user = request.user
        if user.is_superuser:
            users = User.objects.filter(Q(is_superuser=False)).values()
            response = {
                'status code': status.HTTP_200_OK,
                'users':users
            }
            status_code = status.HTTP_200_OK
            return Response(response, status=status_code)
        else:
            response = {
                'status code': status.HTTP_401_UNAUTHORIZED,
            }
            status_code = status.HTTP_401_UNAUTHORIZED
            return Response(response, status=status_code)

class UpdatePasswordView(APIView):
    permission_classes = (IsAuthenticated,)
    def post(self, request, id):
        admin = request.user
        try:
            password = request.data['password']
        
            if admin.is_superuser:
                user = User.objects.filter(Q(id=id)).first()
                user.set_password(password)
                user.save()
                status_code = status.HTTP_200_OK
                response = {
                    'status code': status.HTTP_200_OK,
                }
                return Response(response, status=status_code)
            else:
                response = {
                    'status code': status.HTTP_401_UNAUTHORIZED,
                }
                status_code = status.HTTP_401_UNAUTHORIZED
                return Response(response, status=status_code)
        except Exception as e:
            print(str(e))

class PageData(APIView):
    permission_classes = (AllowAny,)
    def get(self, request):
        settingss = PageSetting.objects.all().values() 
        response = {
            'status code': status.HTTP_200_OK,
            'settings':settingss
        }
        status_code = status.HTTP_200_OK
        return Response(response, status=status_code)

class UpdatePriceView(APIView):
    permission_classes=(IsAuthenticated,)
    def post(self, request):
        user = request.user
        id = request.data['price_id']
        procut = Product.objects.filter(Q(seller = user) & Q(id = id)).first()
        
        price = stripe.Price.create(
            product=procut.product_id,
            unit_amount=request.data['updatedata'],
            currency="JPY",
        )
        procut.price_id = price.id
        procut.price_sell = request.data['updatedata']
        procut.save()
        status_code = status.HTTP_200_OK
        response = {
            'status code': status.HTTP_200_OK,
        }
        return Response(response, status=status_code)
    
class UpdateTitleView(APIView):
    permission_classes=(IsAuthenticated,)
    def post(self, request):
        user = request.user
        id = request.data['price_id']
        procut = Product.objects.filter(Q(seller = user) & Q(id = id)).first()
        procut.title = request.data['updatedata']
        procut.save()
        status_code = status.HTTP_200_OK
        response = {
            'status code': status.HTTP_200_OK,
        }
        return Response(response, status=status_code)
    
class UpdatePageSettingView(APIView):
    permission_classes=(IsAuthenticated,)
    def post(self, request):
        updatedata = request.data['updatedata']
        key = request.data['key']
        setting, created = PageSetting.objects.update_or_create(
            key=key, defaults={"value": updatedata}
        )
        status_code = status.HTTP_200_OK
        response = {
            'status code': status.HTTP_200_OK,
        }
        return Response(response, status=status_code)

    
class UpdateSubtitleView(APIView):
    permission_classes=(IsAuthenticated,)
    def post(self, request):
        user = request.user
        id = request.data['price_id']
        procut = Product.objects.filter(Q(seller = user) & Q(id = id)).first()
        procut.package = request.data['updatedata']
        procut.save()
        status_code = status.HTTP_200_OK
        response = {
            'status code': status.HTTP_200_OK,
        }
        return Response(response, status=status_code)

class UpdateDescriptionView(APIView):
    permission_classes=(IsAuthenticated,)
    def post(self, request):
        user = request.user
        id = request.data['price_id']
        procut = Product.objects.filter(Q(seller = user) & Q(id = id)).first()
        procut.description = request.data['updatedata']
        procut.save()
        status_code = status.HTTP_200_OK
        response = {
            'status code': status.HTTP_200_OK,
        }
        return Response(response, status=status_code)
    
class UpdateImageView(APIView):
    permission_classes=(IsAuthenticated,)
    def post(self, request):
        user = request.user
        id = request.data['price_id']
        key = request.data['key']
        imageFile = request.FILES.get('img', '')
        img = ''
        fs = FileSystemStorage()
        procut = Product.objects.filter(Q(seller = user) & Q(id = id)).first()
        if imageFile:
            img = fs.save(imageFile.name, imageFile)
            if(key=="image"):
                procut.image = "https://royaljapan.asia/media/" + img
            if(key=="image1"):
                procut.image1 = "https://royaljapan.asia/media/" + img
            if(key=="image2"):
                procut.image2 = "https://royaljapan.asia/media/" + img
            if(key=="image3"):
                procut.image3 = "https://royaljapan.asia/media/" + img
        procut.save()
        status_code = status.HTTP_200_OK
        response = {
            'status code': status.HTTP_200_OK,
        }
        return Response(response, status=status_code)
    
class UpdateDeliverImageView(APIView):
    permission_classes=(IsAuthenticated,)
    def post(self, request):
        key = request.data['key']
        imageFile = request.FILES.get('img', '')
        img = ''
        fs = FileSystemStorage()
        if imageFile:
            img = fs.save(imageFile.name, imageFile)
            imageurl = "https://royaljapan.asia/media/" + img
            try:
                setting, created = PageSetting.objects.update_or_create(
                    key=key, defaults={"value": imageurl}
                )
            except Exception as e:
                print(str(e))
        status_code = status.HTTP_200_OK
        response = {
            'status code': status.HTTP_200_OK,
        }
        return Response(response, status=status_code)
    
 
class UpdateCouponView(APIView):
    permission_classes = (IsAuthenticated,)
    def post(self, request):
        user = request.user
        coupons = Coupon.objects.filter(Q(user = user))
        for coupon in coupons:
            code = random_with_N_digits(8)
            coupon.code = code
            coupon.save()
        status_code = status.HTTP_200_OK
        response = {
            'success': 'True',
            'status code': status_code,
        }
        return Response(response, status=status_code)

class CouponView(APIView):
    permission_classes = (AllowAny,)
    def post(self, request):
        user_id = request.data['user']
        coupon_code = request.data['coupon']
        seller = User.objects.filter(Q(id=user_id)).first()
        coupon = Coupon.objects.filter(Q(code = coupon_code) & Q(user = seller)).first()
        status_code = status.HTTP_200_OK
        response = {
            'percent':coupon.percent,
            'status code': status.HTTP_200_OK,

        }
        return Response(response, status=status_code)

class GetUserProduct(APIView):
    permission_classes = (AllowAny,)
    def get(self, request, id):
        user = User.objects.filter(Q(id=id)).first()
        products = Product.objects.filter(Q(seller = user)).values()
        status_code = status.HTTP_200_OK
        response = {
            'products':products,
            'status code': status.HTTP_200_OK,

        }
        return Response(response, status=status_code)

class GetProduct(APIView):
    permission_classes = (AllowAny,)
    def get(self, request, id):
        product = Product.objects.filter(Q(id=id)).first()
        
        status_code = status.HTTP_200_OK
        response = {
            'price_sell':product.price_sell,
            'price_id':product.price_id,
            'description':product.description,
            'title':product.title,
            'image':product.image,
            'image1':product.image1,
            'image2':product.image2,
            'image3':product.image3,
            'package':product.package,
            'product_id':product.product_id,
            'status code': status.HTTP_200_OK,

        }
        return Response(response, status=status_code)

class CreatePaymentIntentView(APIView):
    permission_classes = (AllowAny,)
    def post(self, request):
        product_id = request.data['product']
        coupon_code = request.data['coupon']
        count = int(request.data['count'])
        product = Product.objects.filter(Q(id=product_id)).first()
        seller = product.seller
        coupon = Coupon.objects.filter(Q(code = coupon_code) & Q(user = seller)).first()
        price_id = product.price_id
        price = stripe.Price.retrieve(price_id)
        if coupon:
            sell_price = (price['unit_amount'] * (100 - coupon.percent) / 100) * count
        else:
            sell_price = price['unit_amount'] * count
        print(sell_price)
        customer = stripe.Customer.create()
        try:
            intent = stripe.PaymentIntent.create(
                amount=int(sell_price),
                customer=customer['id'],
                currency=price['currency'], 
                automatic_payment_methods={"enabled": True}
            )
        except Exception as e:
            print(str(e)) 
        status_code = status.HTTP_200_OK
        response = {
            'clientSecret':intent['client_secret'],
            'status code': status.HTTP_200_OK,

        }
        return Response(response, status=status_code)

class CompletePayment(APIView):
    permission_classes = (AllowAny,)
    def post(self, request):
        product_id = request.data['product']
        coupon_code = request.data['coupon']
        name = request.data['name']
        email = request.data['email']
        phone = request.data['phone']
        address = request.data['address']
        address1 = request.data['address1']
        count = int(request.data['count'])
        product = Product.objects.filter(Q(id=product_id)).first()
        seller = product.seller
        coupon = Coupon.objects.filter(Q(code = coupon_code) & Q(user = seller)).first()
        price_id = product.price_id
        price = stripe.Price.retrieve(price_id)
        sell_price = 0
        if coupon:
            sell_price = (price['unit_amount'] * (100 - coupon.percent) / 100) * count
        else:
            sell_price = price['unit_amount'] * count
        if coupon:
            coupon = coupon
        else:
            coupon = None
        Sold.objects.create(
            product_id = product,
            coupon_id = coupon
        )
        product.sold_count = product.sold_count + count
        product.save()
        try:
            from_email = settings.DEFAULT_FROM_EMAIL
            subject = '【RoyalJapan】 注文完了のお知らせ'
            body_html = '''
                <html lang="en">
                <body style="background-color:#1890ff33; padding:0;margin:0;">
                    <div style="
                    max-width: 900px;
                    margin-top: 50px;
                    margin-bottom:50px;
                    margin-left: auto;
                    margin-right: auto;
                    background-color: #fff;
                    padding-top:25px;
                    padding-bottom:50px;
                    padding-left: 5vw;
                    padding-right: 5vw;
                    box-sizing: border-box;">
                        <div style="text-align:center; padding-top:25px; width:100%;">
                            <img src="cid:logo.png" alt="logo" style="width:350px;">
                        </div>
                        <p style="font-size:20px;font-weight: bold;color:#333;text-align: center;">注文完了しました！<br>
                        </p>
                        <div style="text-align:center;margin-top:25px">
                            お客様のお名前: ''' + name + '''<br/>
                            お客様のメールアドレス: ''' + email + '''<br/>
                            お客様の発送先の住所: ''' + address + '''<br/>
                            お客様の住所: ''' + address1 + '''<br/>
                            お客様の電話番号: ''' + str(phone) + '''<br/><br/>
                            紹介者の名前: ''' + seller.username + '''<br/>
                            紹介者のメールアドレス: ''' + seller.email + '''<br/>
                            価格: ''' + str(sell_price) + '''<br/>
                            商品名: ''' + product.title + '''<br/>                        
                        </div>
                    
                    </div>
                </body>
                </html>'''
            msg = EmailMultiAlternatives(
                subject,
                body_html,
                from_email=from_email,
                to=["yoshinoharuki0714@gmail.com" ,"keeper0314@gmail.com"]
            )
            msg.mixed_subtype = 'related'
            msg.attach_alternative(body_html, "text/html")
            img_dir = 'static'
            image = 'logo.png'
            file_path = os.path.join(img_dir, image)
            with open(file_path, 'rb') as f:
                img = MIMEImage(f.read())
                img.add_header('Content-ID', '<{name}>'.format(name=image))
                img.add_header('Content-Disposition', 'inline', filename=image)
            msg.attach(img)
            msg.send()
        except Exception as e:
            print(str(e))
        status_code = status.HTTP_200_OK
        response = {
            'status code': status.HTTP_200_OK,
        }
        return Response(response, status=status_code)
    
class StripeWebHookView(APIView):
    permission_classes = (AllowAny,)
    def post(self, request):
        payload = request.body
        event = None       
        try:
            event = stripe.Event.construct_from(
                json.loads(payload), stripe.api_key
            )
        except ValueError as e:            
            status_code = status.HTTP_400_BAD_REQUEST
            response = {
                'status code': status.HTTP_400_BAD_REQUEST,
            }
            return Response(response, status=status_code)
        
        if event.type == 'payment_intent.requires_action':
            payment_intent = event.data.object
            
        elif event.type == 'payment_intent.succeeded':
            payment_intent = event.data.object
            
        print(str(event.type))
        status_code = status.HTTP_200_OK
        response = {
            'status code': status.HTTP_200_OK,
        }
        return Response(response, status=status_code)

def random_with_N_digits(n):
    range_start = 10**(n-1)
    range_end = (10**n)-1
    return str(randint(range_start, range_end))
