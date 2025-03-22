from . import update
from django.urls import path
from royal.api.views import *
urlpatterns = [
    path('login', UserLoginView.as_view()),
    path('admin/login', AdminLoginView.as_view()),
    path('register', UserRegisterView.as_view()),
    path('get-user-data', GetMyDataView.as_view()),
    path('get-user-data/<uuid:id>', UserView.as_view()),
    path('get-users', GetUserDataView.as_view()),
    path('update-password/<uuid:id>', UpdatePasswordView.as_view()),
    path('update-price', UpdatePriceView.as_view()),
    path('update-title', UpdateTitleView.as_view()),
    path('update-subtitle', UpdateSubtitleView.as_view()),
    path('update-description', UpdateDescriptionView.as_view()),
    path('update-image', UpdateImageView.as_view()),
    path('update-page', UpdatePageSettingView.as_view()),
    path('get-page-data', PageData.as_view()),
    path('update-deliver-img', UpdateDeliverImageView.as_view()),
    path('update-coupon', UpdateCouponView.as_view()),
    path('coupon', CouponView.as_view()),
    path('user-products/<uuid:id>', GetUserProduct.as_view()),
    path('product/<int:id>', GetProduct.as_view()),
    path('create-payment-intent', CreatePaymentIntentView.as_view()),
    path('sold', CompletePayment.as_view()),
    path('webhook', StripeWebHookView.as_view()),
    
]

update.start()
