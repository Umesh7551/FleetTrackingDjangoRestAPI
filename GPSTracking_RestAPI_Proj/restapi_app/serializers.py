import hashlib

from django.db import models
from rest_framework import serializers
from .models import FleetOwner, Car, GPSTracker, Tracker_data, Driver, RFID, Zone


class FleetOwnerSerializer(serializers.ModelSerializer):
    class Meta:
        model = FleetOwner
        fields = '__all__'


class CarSerializer(serializers.ModelSerializer):
    class Meta:
        model = Car
        fields = '__all__'


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

class FleetOwnerRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = FleetOwner
        fields = ['first_name', 'last_name', 'email', 'password', 'contact_number', 'address', 'aadhar_number', 'pan_number', 'resident_proof']

    def create(self, validated_data):
        validated_data['password'] = hashlib.sha256(validated_data['password'].encode()).hexdigest()
        return FleetOwner.objects.create(**validated_data)

class FleetOwnerLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    tokens = serializers.DictField(read_only=True)

    def validate(self, data):
        email = data.get('email')
        password = hashlib.sha256(data.get('password').encode()).hexdigest()
        user = FleetOwner.objects.filter(email=email, password=password).first()
        if not user:
            raise serializers.ValidationError("Invalid login credentials.")
        user.last_login = models.DateTimeField(auto_now=True)
        user.save()
        data['tokens'] = user.tokens()
        return data