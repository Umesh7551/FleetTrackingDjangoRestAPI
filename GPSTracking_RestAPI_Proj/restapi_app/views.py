from django.contrib.sites.shortcuts import get_current_site
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import UserRegistrationSerializer, DeactivateAccountSerializer, UserProfileSerializer, CarSerializer, DriverSerializer
from .tokens import token_generator  # Custom token generator
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework.decorators import api_view, permission_classes
from .models import Car, Tracker_data, GPSTracker, RFID, Zone, Driver


# class RegisterUserView(APIView):
    # def post(self, request):
    #     serializer = UserRegistrationSerializer(data=request.data)
    #     if serializer.is_valid():
    #         serializer.save()
    #         return Response({"message":"User is registered successfully!!!"}, status=status.HTTP_201_CREATED)
    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserRegistrationView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            # Generate email activation link
            current_site = get_current_site(request)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = token_generator.make_token(user)
            activation_link = reverse('activate', kwargs={'uidb64': uid, 'token': token})
            activation_url = f"http://{current_site.domain}{activation_link}"

            # Send Mail
            mail_subject = "Activate your account."
            message = render_to_string('accounts/activation_email.html', {
                'user': user,
                'activation_url': activation_url,
            })
            email = EmailMessage(mail_subject, message, to=[user.email])
            email.send()

            return Response({'message': 'Please confirm your email to complete registration.'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ActivateAccountView(APIView):
    permission_classes = [AllowAny]
    def get(self, request, uidb64, token, *args, **kwargs):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            return Response({'message': 'Your account has been activated successfully.'}, status=status.HTTP_200_OK)
        return Response({'error': 'Activation link is invalid!'}, status=status.HTTP_400_BAD_REQUEST)


class LoginUserAPIView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        # Get the username and password from request data
        username = request.data.get('username')
        password = request.data.get('password')

        # Authenticate the user
        user = authenticate(request, username=username, password=password)

        if user is not None:
            # if user.is_active:
            #     # Generate JWT Token
            #     refresh = RefreshToken.for_user(user)
            #     access_token = str(refresh.access_token)
            #     return Response({
            #         'refresh_token': str(refresh),
            #         'access_token': str(refresh.access_token),
            #         'message': "Login Successful!!!"
            #     }, status=status.HTTP_200_OK)
            # else:
            #     return Response({'error': "Account is not activated yet."}, status=status.HTTP_403_FORBIDDEN)
            if user.is_active:
                # Generate JWT Token
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)

                # Set refresh token in an HTTP-only cookie
                response = JsonResponse({
                    'access_token': access_token,
                    'message': "Login Successful!!!"
                }, status=status.HTTP_200_OK)
                response.set_cookie(
                    key='refresh_token',
                    value=str(refresh),
                    httponly=True,  # Prevent JavaScript access
                    secure=True,  # Use HTTPS in production
                    samesite='Lax',  # Protect against CSRF (can adjust to 'Strict' based on requirements)
                    max_age=60 * 60 * 24 * 7  # Cookie expires in 7 days
                )
                return response
            else:
                return Response({'error': "Account is not activated yet."}, status=status.HTTP_403_FORBIDDEN)
        else:
            return Response({'error': "Invalid Credentials."}, status=status.HTTP_401_UNAUTHORIZED)

class RoleBasedLoginUserAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        # Authenticate User
        user = authenticate(request, username=username, password=password)

        if user is not None:
            if user.is_active:
                # Generate JWT Token
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)

                # Determine user's group and dashboard url
                if user.groups.filter(name='ed_admin').exists():
                    dashboard_url = '/ed_admin_dashboard'
                elif user.groups.filter(name='ed_admin_support_person').exists():
                    dashboard_url = '/ed_admin_support_dashboard'
                elif user.groups.filter(name='fleetowner').exists():
                    dashboard_url = '/fleetowner_dashboard'
                elif user.groups.filter(name='fleetowner_support_person').exists():
                    dashboard_url = '/fleetowner_support_dashboard'
                else:
                    return JsonResponse({'error': 'Please contact administrator. You have not given permission to access application!!!'}, status=status.HTTP_403_FORBIDDEN)
                return Response({
                    'access_token': access_token,
                    'refresh_token': str(refresh),
                    'message': 'Login Successful!',
                    'dashboard_url': dashboard_url  # Return dashboard URL
                }, status=status.HTTP_200_OK)
            else:
                return JsonResponse({'error': 'Account is not activated. Please activate your account.'}, status=status.HTTP_403_FORBIDDEN)
        else:
            return JsonResponse({'error': 'Invalid username or password.'}, status=status.HTTP_401_UNAUTHORIZED)



class DeactivateAccountView(APIView):
    permission_classes = [IsAuthenticated]   # Ensure the user is authenticated
    def post(self, request):
        serializer = DeactivateAccountSerializer(data=request.data)
        if serializer.is_valid():
            confirm_deactivation = serializer.validated_data.get('confirm_deactivation')

            if confirm_deactivation:
                # Deactivate the user account
                user = request.user
                user.is_active = False
                user.save()
                return Response({'message': 'Your account has been deactivated successfully.'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Please confirm account deactivation.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



# class LogoutUserView(APIView):
#     permission_classes = [IsAuthenticated]
#
#     def post(self, request):
#         try:
#             # Get the refresh token from the request data
#             refresh_token = request.data.get('refresh_token')
#             if not refresh_token:
#                 return Response({'error': 'Refresh token is required.'}, status=status.HTTP_400_BAD_REQUEST)
#
#             # Blacklist the refresh token
#             token = RefreshToken(refresh_token)
#             token.blacklist()
#
#             return Response({'message': 'User is logged out successfully.'}, status=status.HTTP_200_OK)
#         except Exception as e:
#             return Response({'error': 'Invalid token or token already blacklisted'}, status=status.HTTP_400_BAD_REQUEST)


class LogoutUserView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        response = JsonResponse({'message': 'Logout successful!'})
        response.delete_cookie('refresh_token')  # Remove the refresh token cookie
        return response


class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Retrieve and serialize the user's profile
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        # Update the user's Profile
        serializer = UserProfileSerializer(instance=request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CarListCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """ Retrieve all cars associated with the authenticated user"""
        cars = Car.objects.filter(owner=request.user)
        serializer = CarSerializer(cars, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        """ Create a new car for the authenticated user. """
        data = request.data
        serializer = CarSerializer(data=data)
        if serializer.is_valid():
            serializer.save(owner=request.user)  # Associate the car with the logged-in user
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CarDetailAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, pk, user):
        try:
            return Car.objects.get(pk=pk, owner=user)
        except Car.DoesNotExist:
            return None

    def get(self, request, pk):
        """Retrieve details of a specific car. """
        car = self.get_object(pk, request.user)
        if not car:
            return Response({'error': 'Car Not Found'}, status=status.HTTP_404_NOT_FOUND)
        serializer = CarSerializer(car)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk):
        """Update a specific car."""
        car = self.get_object(pk, request.user)
        if not car:
            return Response({'error': 'Car not found.'}, status=status.HTTP_404_NOT_FOUND)
        serializer = CarSerializer(car, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        """ Delete a specific car"""
        car = self.get_object(pk, request.user)
        if not car:
            return Response({'error': 'Car not Found.'}, status=status.HTTP_404_NOT_FOUND)
        car.delete()
        return Response({'message': 'Car Deleted successfully. '}, status=status.HTTP_200_OK)


class DriverListCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.groups.filter(name='fleetowner').exists():
            cars = Car.objects.filter(owner=request.user)
            drivers = Driver.objects.filter(car__in=cars)
            serializer = DriverSerializer(drivers, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response({'details': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)

    def post(self, request):
        if request.user.groups.filter(name='fleetowner').exists():
            cars = Car.objects.filter(owner=request.user)
            if not cars.exists():
                return Response({'detail': 'No cars available for the user.'}, status=status.HTTP_400_BAD_REQUEST)

            data = request.data
            serializer = DriverSerializer(data=data)
            if serializer.is_valid():
                driver = serializer.save(car=cars.first())  # Assign the first car
                return Response(DriverSerializer(driver).data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({'detail': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)


class DriverUpdateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, id):
        return get_object_or_404(Driver, id=id)

    def put(self, request, id):
        if request.user.groups.filter(name='fleetowner').exists():
            driver = self.get_object(id)
            serializer = DriverSerializer(Driver, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({'detail': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)


class DriverDeleteAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, id):
        if request.user.groups.filter(name='fleetowner').exists():
            driver = get_object_or_404(Driver, id=id)
            driver.delete()
            return Response({'detail': 'Driver deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)
        return Response({'detail': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)
