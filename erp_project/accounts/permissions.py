from rest_framework import permissions
from .models import User


class IsAdminOrManager(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and (
            request.user.role == User.Role.ADMIN or
            request.user.role == User.Role.MANAGER
        )
