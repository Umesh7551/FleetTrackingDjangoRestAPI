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

