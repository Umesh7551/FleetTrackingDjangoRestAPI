import hashlib
from django.utils import timezone
from django.db import models
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from .models import User, Profile, Car, GPSTracker, Tracker_data, Driver, RFID, Zone


# class UserRegistrationSerializer(serializers.ModelSerializer):
#     password = serializers.CharField(write_only=True, style={'input_type': 'password'})
#
#     class Meta:
#         model = User
#         # fields = '__all__'
#         fields = ['username', 'email', 'password']
#
#     def create(self, validated_data):
#         user = User.objects.create_user(
#             username=validated_data['username'],
#             email=validated_data['email'],
#             password=validated_data['password']
#
#         )
#         return user
class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def validate_email(self, email):
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError('A user with this email already exists.')
        return email

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        user.is_active = False # Set account to in-active
        user.save()
        return user

class DeactivateAccountSerializer(serializers.Serializer):
    confirm_deactivation = serializers.BooleanField(required=True)


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['phone', 'address', 'city', 'state', 'country']

class UserProfileSerializer(serializers.ModelSerializer):
    profile = ProfileSerializer

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'profile']

    def update(self, instance, validated_data):
        profile_data = validated_data.pop('profile', {})
        profile = instance.profile

        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.email = validated_data.get('email', instance.email)
        instance.save()

        for attr, value in profile_data.items():
            setattr(profile, attr, value)
        profile.save()

        return instance



# class CarSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Car
#         fields = '__all__'

class CarSerializer(serializers.ModelSerializer):
    class Meta:
        model = Car
        fields = [
            'id', 'registration_number', 'registration_date', 'vehicle_name',
            'colour', 'model', 'chassis_number', 'tracker', 'insurance', 'puc',
            'seating_capacity', 'fuel_type', 'air_condition', 'owner'
        ]
        read_only_fields = ['id', 'owner']  # Owner will be set to the logged-in user


class GPSTrackerSerializer(serializers.ModelSerializer):
    class Meta:
        model = GPSTracker
        fields = '__all__'


class TrackerDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tracker_data
        fields = '__all__'


class DriverSerializer(serializers.ModelSerializer):
    class Meta:
        model = Driver
        fields = '__all__'


class RFIDSerializer(serializers.ModelSerializer):
    class Meta:
        model = RFID
        fields = '__all__'


class ZoneSerializer(serializers.ModelSerializer):
    class Meta:
        model = Zone
        fields = '__all__'

