from django.urls import path
from .views import RegisterView, LoginView, UserListView, ProfileView, LogoutView
from .views import UserDetailView, login_view, dashboard_view, logout_view, add_user_view
from .views import edit_user_view, delete_user_view

urlpatterns = [
    # API routes
    path('api/register/', RegisterView.as_view(), name='register'),
    path('api/login/', LoginView.as_view(), name='login'),
    path('api/logout/', LogoutView.as_view(), name='logout'),
    path('api/users/', UserListView.as_view(), name='user-list'),
    path('api/profile/', ProfileView.as_view(), name='profile'),
    path('api/users/<int:id>/', UserDetailView.as_view(), name='user-detail'),

    # Frontend template views
    path('login/', login_view, name='login-view'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('logout/', logout_view, name='logout'),
    path('add-user/', add_user_view, name='add-user'),
    path('edit-user/<int:id>/', edit_user_view, name='edit-user'),
    path('delete-user/<int:id>/', delete_user_view, name='delete-user'),
]
