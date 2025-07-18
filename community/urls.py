# urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from community.views import (
    CommunityGroupViewSet,
    CommunityMembershipViewSet,
    CommunityPostViewSet,
    CommunityCommentViewSet,
    CommunityEventViewSet,
    CommunityResourceViewSet,
    CommunityNotificationViewSet,
    CommunityAccessibilitySettingViewSet
)

router = DefaultRouter()
router.register(r'groups', CommunityGroupViewSet)
router.register(r'memberships', CommunityMembershipViewSet)
router.register(r'posts', CommunityPostViewSet)
router.register(r'comments', CommunityCommentViewSet)
router.register(r'events', CommunityEventViewSet)
router.register(r'resources', CommunityResourceViewSet)
router.register(r'notifications', CommunityNotificationViewSet, basename='community-notification')
router.register(r'accessibility', CommunityAccessibilitySettingViewSet, basename='accessibility-settings')

urlpatterns = [
    path('', include(router.urls)),
]
