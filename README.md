
# 🧾 ERP User & Role Management System – Backend (Django + DRF)

## 📚 Overview

This system handles user authentication and **role-based access control** (RBAC) for an ERP platform. Users are assigned roles like `Admin`, `Manager`, or `Employee`, and each role has specific permissions for accessing and managing data.

---

## ⚙️ Tech Stack

- **Backend Framework:** Django + Django REST Framework (DRF)
- **Authentication:** JWT (via `djangorestframework-simplejwt`)
- **Database:** PostgreSQL or MySQL *(project supports both)*
- **Token Blacklisting:** Enabled for logout functionality
- **Frontend:** Handled separately (Django Templates + Tailwind CSS)

---

## 🏁 Setup Instructions

### 1. Clone the Project (Branch with PostGresSQL)

```bash
git clone --branch postgres-db --single-branch https://github.com/KGPraveen/erp.git
cd erp
```

### 2. Create Virtual Environment

```bash
python -m venv env
env/Scripts/activate     # Windows
# source env/bin/activate (Linux/Mac)
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Change Directory

```bash
cd erp_project
```

### 5. Migrate Database

```bash
python manage.py migrate
```

### 6. Run Server

```bash
python manage.py runserver
```

---

## 🔑 Authentication System

- JWT-based login with access and refresh tokens
- Secure logout with refresh token blacklisting
- User registration allowed through API

---

## 🧩 API Endpoints

| Method | URL              | Description                            | Access        |
|--------|------------------|----------------------------------------|---------------|
| POST   | `accounts/api/register/` | Register a new user                    | Public        |
| POST   | `accounts/api/login/`    | Login & receive JWT tokens             | Public        |
| POST   | `accounts/api/logout/`   | Logout (blacklists refresh token)      | Authenticated |
| GET    | `accounts/api/users/`    | List all users                         | Admin, Manager |
| GET    | `accounts/api/profile/`  | View own profile                       | All users     |

### 📌 Token Format

- **Authorization Header:**  
  `Authorization: Bearer <access_token>`

---

## 🧾 Sample Requests (Using Postman)

### 🔐 Login

**POST** `accounts/api/login/`  
```json
{
  "username": "adminfox",
  "password": "admin123"
}
```

✅ Returns:
```json
{
  "access": "<JWT access token>",
  "refresh": "<JWT refresh token>"
}
```

---

### 🚪 Logout

**POST** `accounts/api/logout/`  
(Requires access token in Authorization header)

```json
{
  "refresh": "<refresh token here>"
}
```

---

## 🛡️ Role-Based Access Control (RBAC)

| Role      | Permissions                                                  |
|-----------|--------------------------------------------------------------|
| **Admin** | - Register users<br>- View/Edit/Delete all users             |
| **Manager** | - View all **employees** only                              |
| **Employee** | - View own profile only                                   |

Users are assigned roles during registration and validated via custom claims in JWT tokens.

---

## 🧠 How JWT Roles Work

The system adds a custom `role` field to every access token payload, like so:

```json
{
  "token_type": "access",
  "exp": 1234567890,
  "jti": "...",
  "user_id": 2,
  "username": "adminfox",
  "role": "ADMIN"
}
```

Frontend uses this to redirect and secure views accordingly.

---

## ⚠️ Notes

- Superusers (`is_staff`, `is_superuser`) can be created via `createsuperuser`, but are separate from the app’s role logic.
- Employees **cannot access user list** — will get 403 Forbidden.
- Token refresh and logout both handled securely.

---

&nbsp;

&nbsp;

# 🔮 Frontend Features (Template-Based)

The frontend was built using Django templates and Bootstrap for responsive design.

### 🎯 Functionality

- **Login Page**:
  - Authenticates users using the backend API (`accounts/api/login/`).
  - Displays helpful error messages on invalid login.
  
- **Role-Based Dashboards**:
  - **Admin Dashboard**:
    - View all users.
    - Add new users (with role, email, first/last name).
    - Edit and delete existing users.
  - **Manager Dashboard**:
    - View-only access to employee list.
  - **Employee Dashboard**:
    - View their own profile.

- **Logout**:
  - Clears session tokens and redirects to login.

- **Route Protection**:
  - Users without tokens are redirected to login.
  - Role-based redirection handled in views.

### 🖌️ UI & Styling

- Built with **Bootstrap 5** (CDN linked).
- Responsive layout with:
  - Centered login form.
  - Scrollable tables on smaller screens.
  - Proper padding/margins across forms and tables.

---

### 🚦 How it Works

1. **Login Form** (template: `login.html`)  
   
   Sends credentials to `accounts/api/login/` and stores JWT in Django session.

2. **Dashboard** (template: `admin_dashboard.html`, etc.)  
   
   Uses token to fetch user role and relevant data from `accounts/api/profile/` and `accounts/api/users/`.

3. **Add/Edit/Delete**  
   
   Uses `POST`, `PUT`, and `DELETE` calls to backend API endpoints, protected by the access token.

---

### 🔐 Security Notes

- All dashboard and user management views check for a valid token in the session.
- CSRF protection enabled for all forms, except where using JSON API calls.

---
