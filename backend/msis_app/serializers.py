from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .models import *


def custom_response(success=True, statusCode=200, message="Operation successful", data=None):
    return Response({
        "success": success,
        "statusCode": statusCode,
        "message": message,
        "data": data
    }, status=status.HTTP_200_OK)

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        # Add custom claims
        token['username'] = user.username
        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        data['username'] = self.user.username 
        return data

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'name', 'username', 'email', 'is_activated', 'is_superuser', 'is_deleted')


class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'password', 'name', 'email', 'factories')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        userName = validated_data['username']
        passWord = validated_data['password']
        name = validated_data['name']
        factories = validated_data.pop('factories', [])
        emailAdd = validated_data['email']
        if not userName or not passWord:
            return custom_response(False, 400, 'username and password are required')
        
        if User.objects.filter(username=userName).exists():
            return custom_response(False, 409, f'User with this username ({userName}) already exists')

        if emailAdd and User.objects.filter(email=emailAdd).exists():
            return Response({'status': 'error', 'message': f'User with this email address ({emailAdd}) already exists'}, status=status.HTTP_409_CONFLICT)

        user = User(**validated_data)
        user.set_password(passWord)
        user.save()
        user.factories.set(factories)
        return user

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        username = data.get("username")
        password = data.get("password")

        # Get the custom user model
        MyUser = get_user_model()

        # Find the user by username
        user = MyUser.objects.filter(username=username).first()

        # Validate user existence and password
        if not user or user is None:
            raise serializers.ValidationError(f"User not found with username: {username}")
        if not user.check_password(password):
            raise serializers.ValidationError("Incorrect password. Please, check and try again.")
        # Check if the user's account is activated
        if not user.is_activated:
            raise serializers.ValidationError("User account is not activated.")

        # Attach the user object to the validated data
        data['user'] = user
        return data

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, email_address):

        # Get the custom user model
        MyUser = get_user_model()

        if not MyUser.objects.filter(email=email_address).exists():
            raise serializers.ValidationError("No user is associated with this email address: " + email_address)
        return email_address

class PasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)
    token = serializers.CharField()
    uidb64 = serializers.CharField()

    def validate(self, data):
        try:
            uid = force_str(urlsafe_base64_decode(data['uidb64']))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError("Invalid token or user ID")

        if not PasswordResetTokenGenerator().check_token(user, data['token']):
            raise serializers.ValidationError("Invalid token or expired")

        return data

    def save(self, **kwargs):
        uid = force_str(urlsafe_base64_decode(self.validated_data['uidb64']))
        user = User.objects.get(pk=uid)
        user.set_password(self.validated_data['password'])
        user.save()        

class FindUsernameSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, email_address):

        MyUser = get_user_model()

        user = MyUser.objects.filter(email=email_address).first()
        if not user:
            # print(f'Error here: No user is associated with this email address: {email_address}')
            raise serializers.ValidationError("No user is associated with this email address: " + email_address)
        print('serializer username: ', user.username)
        return user.username

class UserSerializer(serializers.ModelSerializer):
    approved_by = serializers.StringRelatedField()
    updated_by = serializers.StringRelatedField()
    factories = serializers.SlugRelatedField(
        many=True,
        slug_field='name',  # or 'id' if you want factory IDs
        queryset=Factory.objects.all(),
    )
    class Meta:
        model = User
        fields = ['id', 'username', 'name', 'email', 'is_superuser', 'is_staff', 'is_activated', 'created_at', 'updated_at', 'approved_by', 'updated_by', 'last_login', 'factories', 'is_deleted']
        extra_kwargs = {'password': {'write_only': True}}

class FactorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Factory
        fields = '__all__'


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = '__all__'


class MachineSerializer(serializers.ModelSerializer):
    class Meta:
        model = Machine
        fields = '__all__'


class UpdateMachineNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = Machine
        fields = ['title']
        extra_kwargs = {
            'title': {'required': True, 'allow_blank': False}
        }

class CameraSerializer(serializers.ModelSerializer):
    class Meta:
        model = Camera
        fields = '__all__'
        

class UpdateCameraNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = Camera
        fields = ['name']
        extra_kwargs = {
            'name': {'required': True, 'allow_blank': False}
        }


class DMoldSerializer(serializers.ModelSerializer):
    class Meta:
        model = DMold
        fields = '__all__'

class DPinArrivalSerializer(serializers.ModelSerializer):
    class Meta:
        model = DPinArrival
        fields = '__all__'

class DAirbagSerializer(serializers.ModelSerializer):
    class Meta:
        model = DAirbag
        fields = '__all__'

class DPcbSerializer(serializers.ModelSerializer):
    class Meta:
        model = DPcb
        fields = '__all__'

class DReelPackagingSerializer(serializers.ModelSerializer):
    class Meta:
        model = DReelPackaging
        fields = '__all__'
