from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
from .views import FleetOwnerView

urlpatterns = [
    path('fleet_owners', FleetOwnerView.as_view(), name='fleet_owners'),
    path('fleet_owners/<int:id>', FleetOwnerView.as_view(), name='fleet_owners')
]




if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)