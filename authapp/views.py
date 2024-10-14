from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from authapp.serializers import *
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import render

def get_tokens_for_user(user):
    refresh=RefreshToken.for_user(user)
    return {
        'refresh':str(refresh),
        'access':str(refresh.access_token),
    }

#Register
class UserRegistrationView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data = request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'msg': 'Registration Successful'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)

#Login
class UserLoginView(APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data= request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            print(user)
            token = get_tokens_for_user(user)
            return Response({
                            'token':token,
                            'user' : {
                              'email' : user.email,
                              'first_name' : user.first_name,
                              'last_name' : user.last_name,
                            },
                            'msg':"Login Success"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#Logout
class UserLogoutView(APIView):
    def post(self,request):
        refresh_token = request.data.get('refresh_token')
        if refresh_token is None:
            return Response({'error':"Refresh token is required"},status=status.HTTP_400_BAD_REQUEST)
        token = RefreshToken(refresh_token)
        token.blacklist()
        return Response ({'message':'Logged Out Successfully'})


# Send Reset Password email Request
class SendForgotPasswordEmailView(APIView):
    def post(self, request):
        serializer = SendForgotPasswordMailSerializer(data= request.data)
        if serializer.is_valid():
            return Response({'msg':'Password reset link sent . Please check your email '}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Password Reset Done 
class resetpassword(APIView):
    def post (self, request, uid, token):
        print('uid',uid)
        print('token',token)
        serializer = ForgotPasswordDoneSerializer(data = request.data, context = {'uid':uid,'token':token})
        if serializer.is_valid():
            return Response({'msg':'Password reset successfully '}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def test(request):
    return render(request, 'index.html')