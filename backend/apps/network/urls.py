from django.urls import path

from . import views

urlpatterns = [
    path("network/self/", views.NetworkSelfView.as_view(), name="network-self"),
    path("network/dns/", views.NetworkDnsView.as_view(), name="network-dns"),
    path("network/ip/", views.NetworkIpView.as_view(), name="network-ip"),
    path("network/local-ports/", views.NetworkLocalPortsView.as_view(), name="network-local-ports"),
    path("network/headers/", views.NetworkHeadersView.as_view(), name="network-headers"),
]
