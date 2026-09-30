from rest_framework.routers import DefaultRouter

from .views import DependencyViewSet, FindingViewSet, SecretFindingViewSet

router = DefaultRouter()
router.register(r"findings", FindingViewSet, basename="finding")
router.register(r"dependencies", DependencyViewSet, basename="dependency")
router.register(r"secret-findings", SecretFindingViewSet, basename="secret-finding")

urlpatterns = router.urls
