from django.shortcuts import redirect
from django.shortcuts import render, redirect
# Create your views here.
from rest_framework import status, generics, permissions
from .models import User
from .serializers import RegisterSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .serializers import UserSerializer
from .permissions import IsAdminOrManager
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework.generics import RetrieveUpdateDestroyAPIView
from .permissions import IsAdminUserOnly  # this already exists
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse

import requests


class RegisterView(generics.CreateAPIView):
    # This class-based view comes from DRF's CreateAPIView
    # which is prebuilt to handle POST requests that
    # create new objects in the database — in our case, a new user.

    queryset = User.objects.all()

    serializer_class = RegisterSerializer
    # tells which serializer to use, it handles the
    # Creation, Validation and Serialization/Deserailization

    permission_classes = [permissions.AllowAny]
    # Controls who can access this view.


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    # TokenObtainPairSerializer is SimpleJWT's default serializer for login.
    # It takes in a username and password, Authenticates the user and
    # returns an access token and a refresh token

    def validate(self, attrs):
        data = super().validate(attrs)
        # calls super class' (TokenObtainPairSerializer's) validate function

        data['role'] = self.user.role
        data['username'] = self.user.username
        return data


class LoginView(TokenObtainPairView):
    # This is a built-in class from rest_framework_simplejwt.views
    # It handles login endpoint.

    serializer_class = CustomTokenObtainPairSerializer


class UserListView(generics.ListAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsAdminOrManager]

    def get_queryset(self):
        user = self.request.user
        if user.role == user.Role.ADMIN:
            return User.objects.all().order_by('id')
        elif user.role == user.Role.MANAGER:
            return User.objects.filter(role=User.Role.EMPLOYEE).order_by('id')
        return User.objects.none()

# /profile - all users


class ProfileView(generics.RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user


class LogoutView(APIView):
    # This is the API endpoint for logging out a user by blacklisting their refresh token.

    permission_classes = [permissions.IsAuthenticated]
    # Only authenticated users (with a valid token) are allowed with above permission
    # therefore, allowing below code to be executed.

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(
                {"detail": "Successfully logged out."},
                status=status.HTTP_205_RESET_CONTENT
            )
        except KeyError:
            return Response(
                {"detail": "Refresh token is missing."},
                status=status.HTTP_400_BAD_REQUEST
            )
        except TokenError as e:
            return Response(
                {"detail": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception:
            return Response(
                {"detail": "Unexpected error."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class UserDetailView(RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdminUserOnly]
    lookup_field = 'id'


def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        response = requests.post('http://127.0.0.1:8000/accounts/api/login/', json={
            'username': username,
            'password': password
        })

        if response.status_code == 200:
            data = response.json()
            request.session['access'] = data['access']
            request.session['refresh'] = data['refresh']
            return redirect('dashboard')
        else:
            return render(request, 'login.html', {'error': 'Invalid credentials'})

    return render(request, 'login.html')


def dashboard_view(request):
    token = request.session.get('access')
    if not token:
        return redirect('login-view')

    headers = {
        'Authorization': f'Bearer {token}'
    }

    res = requests.get(
        'http://127.0.0.1:8000/accounts/api/profile/', headers=headers)
    if res.status_code != 200:
        return redirect('login-view')

    user_data = res.json()
    role = user_data.get('role')

    if role == 'ADMIN':
        users_res = requests.get(
            'http://127.0.0.1:8000/accounts/api/users/', headers=headers)
        if users_res.status_code == 200:
            users = users_res.json()
            return render(request, 'admin_dashboard.html', {'users': users})
        return HttpResponse("Failed to fetch users.")

    elif role == 'MANAGER':
        users_res = requests.get(
            'http://127.0.0.1:8000/accounts/api/users/', headers=headers)
        if users_res.status_code == 200:
            all_users = users_res.json()
            employees = [u for u in all_users if u['role'] == 'EMPLOYEE']
            return render(request, 'manager_dashboard.html', {'employees': employees})
        return HttpResponse("Failed to fetch employee list.")

    elif role == 'EMPLOYEE':
        return render(request, 'employee_dashboard.html', {'user': user_data})

    else:
        return HttpResponse("Unknown role.")


def logout_view(request):
    request.session.flush()
    return redirect('login-view')


@csrf_exempt
def add_user_view(request):
    token = request.session.get('access')
    if not token:
        return redirect('login-view')

    if request.method == 'POST':
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        body = {
            'username': request.POST['username'],
            'email': request.POST['email'],
            'first_name': request.POST['first_name'],
            'last_name': request.POST['last_name'],
            'password': request.POST['password'],
            'role': request.POST['role']
        }
        res = requests.post(
            'http://127.0.0.1:8000/accounts/api/register/', headers=headers, json=body)
        if res.status_code == 201:
            return redirect('dashboard')
        else:
            return HttpResponse("Failed to create user.")

    return render(request, 'add_user.html')


def edit_user_view(request, id):
    token = request.session.get('access')
    if not token:
        return redirect('login-view')

    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    user_api_url = f'http://127.0.0.1:8000/accounts/api/users/{id}/'

    if request.method == 'POST':
        body = {
            'username': request.POST['username'],
            'email': request.POST['email'],
            'first_name': request.POST['first_name'],
            'last_name': request.POST['last_name'],
            'role': request.POST['role']
        }

        new_password = request.POST.get('password')
        if new_password:
            body['password'] = new_password
        print(new_password)
        print(body)

        res = requests.put(user_api_url, headers=headers, json=body)
        if res.status_code == 200:
            return redirect('dashboard')
        else:
            return HttpResponse("Failed to update user.")

    res = requests.get(user_api_url, headers=headers)
    if res.status_code == 200:
        user_data = res.json()
        return render(request, 'edit_user.html', {'user': user_data})
    return HttpResponse("User not found.")


def delete_user_view(request, id):
    token = request.session.get('access')
    if not token:
        return redirect('login-view')

    headers = {
        'Authorization': f'Bearer {token}'
    }

    user_api_url = f'http://127.0.0.1:8000/accounts/api/users/{id}/'
    res = requests.delete(user_api_url, headers=headers)

    return redirect('dashboard')


def root_redirect_view(request):
    if request.session.get('access'):
        return redirect('dashboard')
    else:
        return redirect('login-view')
