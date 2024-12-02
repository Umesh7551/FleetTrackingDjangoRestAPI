from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import UserRegistrationView, ActivateAccountView, LoginUserAPIView, DeactivateAccountView, LogoutUserView, \
    UserProfileView, CarListCreateAPIView, CarDetailAPIView, DriverListCreateAPIView, DriverUpdateAPIView, \
    DriverDeleteAPIView

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('activate/<str:uidb64>/<str:token>/', ActivateAccountView.as_view(), name='activate'),
    path('login/', LoginUserAPIView.as_view(), name='login'),
    path('deactivate_account/', DeactivateAccountView.as_view(), name='deactivate_account'),
    path('logout/', LogoutUserView.as_view(), name='logout'),
    path('profile/', UserProfileView.as_view(), name='user_profile'),
    path('cars/', CarListCreateAPIView.as_view(), name='cars'),
    path('cars/<int:pk>/', CarDetailAPIView.as_view(), name='car_detail'),
    path('drivers/', DriverListCreateAPIView.as_view(), name='driver_list_create'),
    path('drivers/<int:id>/', DriverUpdateAPIView.as_view(), name='driver_update'),
    path('drivers/<int:id>/delete/', DriverDeleteAPIView.as_view(), name='driver_delete'),



]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
