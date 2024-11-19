from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
# from .views import FleetOwnerView
# from .views import FleetOwnerRegisterView, FleetOwnerLoginView, FleetOwnerView

urlpatterns = [
    # path('fleet_owners', FleetOwnerView.as_view(), name='fleet_owners'),
    # # path('fleet_owners/<int:id>', FleetOwnerView.as_view(), name='fleet_owners')
    # path('register/', FleetOwnerRegisterView.as_view(), name='fleetowner-register'),
    # path('login/', FleetOwnerLoginView.as_view(), name='fleetowner-login'),
]




if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)