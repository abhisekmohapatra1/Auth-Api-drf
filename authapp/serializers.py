from rest_framework import serializers
from authapp.models import Users
from django.contrib.auth import authenticate
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.utils.encoding import force_bytes,force_str,DjangoUnicodeDecodeError
from django.contrib.auth.tokens import default_token_generator
from django.conf import settings
from django.core.mail import send_mail


class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'})

    class Meta:
        model = Users
        fields = ['email','first_name','last_name','password', 'password2']

    def validate_first_name(self,value):
        for i in value:
            if i.isdigit():
                raise serializers.ValidationError("It can't contain numbers")
        return value

    def validate_last_name(self,value):
        for i in value:
            if i.isdigit():
                raise serializers.ValidationError("It can't contain numbers ")
        return value

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')

        if len(password)<8:
            raise serializers.ValidationError('Password length should be of minimum 8 characters')

        if not any(x.isupper() for x in password):
            raise serializers.ValidationError("Password Should contain one Upper Case letter")

        if not('@' or '#' or '$')  in password:
            raise serializers.ValidationError("Password should contain atleast One Special Character . Only @ or $ or # are allowed ")

        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password didn't match")
        return attrs

    def create(self, validated_data):
        password = validated_data.pop('password')
        password2 = validated_data.pop('password2')
        user = Users(**validated_data)
        user.set_password(password)
        user.save()
        return user

class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=50)
    
    class Meta:
        model = Users
        fields = ['email', 'password']

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        user = authenticate( email=email , password=password )  # Use email as username
        print('user',user)
        if user is None:
            raise serializers.ValidationError("Invalid credentials")

        data['user'] = user
        return data

class SendForgotPasswordMailSerializer(serializers.Serializer):
    email = serializers.CharField(max_length = 255)
    class Meta:
        fields = ['email']

    def validate(self,data):
        email = data.get('email')
        if Users.objects.filter(email=email).exists():
            user = Users.objects.get(email=email)
            print('user',user.id)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = default_token_generator.make_token(user)
            subject = "Reset Password Link"
            message = f"Hi, Please click on the link to reset your password: http://127.0.0.1:8000/api/resetpassword/{uid}/{token}/" 
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [email]
            send_mail(subject, message, email_from, recipient_list)
        else:
            raise serializers.ValidationError('Incorrect email provided ')
        return data

class ForgotPasswordDoneSerializer(serializers.Serializer):
    password = serializers.CharField(max_length = 255)
    password2 = serializers.CharField(max_length = 255)

    class Meta:
        fields = ['password', 'password2']

    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        uid = self.context.get('uid')
        token = self.context.get('token')

        print('uid',uid)
        print('tokn',token)
        print(password)
        if password != password2:
            raise serializers.ValidationError('Password and Confirm Password didnot match ')

        id = force_str(urlsafe_base64_decode(uid))
        print('id', id)
        user = Users.objects.get(id = id)
        print('user', user)
        if not default_token_generator.check_token(user,token):
            raise serializers.ValidationError('Token is invalid or expired ')
        user.set_password(password)
        user.save()
        return data