from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import FleetOwner, Car, GPSTracker, Tracker_data, Driver, RFID, Zone
from .serializers import FleetOwnerSerializer, CarSerializer, GPSTrackerSerializer, TrackerDataSerializer, DriverSerializer, RFIDSerializer, ZoneSerializer
from .serializers import FleetOwnerRegisterSerializer, FleetOwnerLoginSerializer


class FleetOwnerRegisterView(generics.CreateAPIView):
    queryset = FleetOwner.objects.all()
    serializer_class = FleetOwnerRegisterSerializer


class FleetOwnerLoginView(generics.GenericAPIView):
    serializer_class = FleetOwnerLoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        print("Serializer========>", serializer)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data, status=status.HTTP_200_OK)

class FleetOwnerView(APIView):
    def get(self, request):
        fleet_owner_list = FleetOwner.objects.all()
        serializer = FleetOwnerSerializer(fleet_owner_list, many=True)
        return Response(serializer.data)
