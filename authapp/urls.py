from django.urls import path
from authapp.views import *

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name= 'login'),
    path('logout/',UserLogoutView.as_view(), name= 'logout'),
    path('',test, name="test"),
    path('forgotpassword/',SendForgotPasswordEmailView.as_view(), name='forgotpassword/'),
    path('resetpassword/<uid>/<token>/',resetpassword.as_view(), name='resetpassword/'),

]