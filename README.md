
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

### 1. Clone the Project

```bash
git clone <your-repo-url>
cd <project-directory>
```

### 2. Create Virtual Environment

```bash
python -m venv env
env\Scripts\activate     # Windows
# source env/bin/activate (Linux/Mac)
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Migrate Database

```bash
python manage.py migrate
```

### 5. Run Server

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
| POST   | `/api/register/` | Register a new user                    | Public        |
| POST   | `/api/login/`    | Login & receive JWT tokens             | Public        |
| POST   | `/api/logout/`   | Logout (blacklists refresh token)      | Authenticated |
| GET    | `/api/users/`    | List all users                         | Admin, Manager |
| GET    | `/api/profile/`  | View own profile                       | All users     |

### 📌 Token Format

- **Authorization Header:**  
  `Authorization: Bearer <access_token>`

---

## 🧾 Sample Requests (Using Postman)

### 🔐 Login

**POST** `/api/login/`  
```json
{
  "username": "adminfox",
  "password": "adminpass123"
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

**POST** `/api/logout/`  
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

## 🔄 To Do (Frontend Phase)

- Responsive UI with TailwindCSS
- Login form and dashboard views per role
- Route protection via custom logic
- Logout button that clears token and calls API
