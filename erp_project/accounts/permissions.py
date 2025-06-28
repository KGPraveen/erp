from rest_framework import permissions
from .models import User
from rest_framework.permissions import BasePermission


class IsAdminOrManager(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and (
            request.user.role == User.Role.ADMIN or
            request.user.role == User.Role.MANAGER
        )


class IsAdminUserOnly(BasePermission):
    """
    Allows access only to users with role = 'ADMIN'
    """

    def has_permission(self, request, view):
        return request.user.is_authenticated and getattr(request.user, 'role', '') == 'ADMIN'
