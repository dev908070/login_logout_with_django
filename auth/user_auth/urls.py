from django.urls import path
from .views import register_user, confirm_email,login_user

urlpatterns = [
    path('register/', register_user, name='register_user'),
    path('confirm/<str:token>/', confirm_email, name='confirm_email'),
    path('login/', login_user, name='login_user'), 
]
