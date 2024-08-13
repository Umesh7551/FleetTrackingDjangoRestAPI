from rest_framework.views import APIView
from rest_framework.response import Response
from .models import FleetOwner, Car, GPSTracker, Tracker_data, Driver, RFID, Zone
from .serializers import FleetOwnerSerializer, CarSerializer, GPSTrackerSerializer, TrackerDataSerializer, DriverSerializer, RFIDSerializer, ZoneSerializer

class FleetOwnerView(APIView):
    def get(self, request):
        fleet_owner_list = FleetOwner.objects.all()
        serializer = FleetOwnerSerializer(fleet_owner_list, many=True)
        return Response(serializer.data)
