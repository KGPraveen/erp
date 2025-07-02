from django.contrib.auth.models import AbstractUser
from django.db import models


'''
===============================================================================================
AbstractUser is a base class provided by Django’s auth framework.
It contains all the fields and functionality of Django’s built-in User model
(username, password, email, etc.) but is abstract, meaning it won’t create a
separate database table on its own — it is designed for us to extend and customize.

I have created a custom user model by subclassing AbstractUser and adding an additional
field called role.

This field uses Django’s TextChoices to define valid options: ADMIN, MANAGER, and EMPLOYEE.
===============================================================================================
'''


class User(AbstractUser):
    # My custom User class that Inherits Django's User class and extends from it for this project.

    class Role(models.TextChoices):
        # A nested class 'Role' that also extends from TextChoices class
        #     which is for creating enumerated choices of below.

        ADMIN = 'ADMIN', 'Admin'
        MANAGER = 'MANAGER', 'Manager'
        EMPLOYEE = 'EMPLOYEE', 'Employee'

        # where 'EMPLOYEE' is stored in database and 'Employee' is the
        # human readable form, shown in admin panels, forms, etc.

        """
            It is an alternative to:
            ROLE_CHOICES = [
                ('ADMIN', 'Admin'),
                ('MANAGER', 'Manager'),
                ('EMPLOYEE', 'Employee'),
            ]
        """

        # models.TextChoices turns these constants into a choices iterable automatically behind the scenes
        #     That’s why you don’t need to wrap them in a list or tuple manually

    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        # Role.choices is referenced here

        default=Role.EMPLOYEE,
    )

    # The above role variable creates a field called 'role' for the User model that is defined above.

    def __str__(self):
        return f"{self.username} ({self.role})"


'''==============================================================================================='''
