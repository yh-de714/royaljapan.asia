from . import update
from django.urls import path
from pushservice.api.views import *
urlpatterns = [
    path('login', UserLoginView.as_view()),
    path('register', UserRegisterView.as_view()),
    path('register/<uuid:id>', UserUpdateView.as_view()),
    path('export-product', ExportProductView.as_view()),
    path('fee/<str:shop>', FeeView.as_view()),
    path('product/<str:shop>', ProductView.as_view()),
    path('ngwords', NGWordView.as_view()),
    path('ngwords/asin', NGAsinView.as_view()),
    path('amazon-token', AmazonTokenView.as_view()),
    path('yahoo-token', YahooTokenView.as_view()),
    path('qoo10-sak', Qoo10SAKView.as_view()),
    path('password', PasswordView.as_view()),
    path('all-users', AllUsersView.as_view()),
    path('all-notifications', AllNotificationsView.as_view()),
    path('notification/<int:item_id>', NotificationHandleView.as_view()),
    path('admin/ngwords', AdminNgWordView.as_view()),
    path('auto-update/<uuid:id>', AutoUdateView.as_view()),
]

update.start()
