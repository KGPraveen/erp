from rest_framework import serializers
# Serializers complex data types (e.g., Django models) to and from native
# Python datatypes that can be easily rendered into JSON, XML, or other formats.

from .models import User
# We import the custom User model that we defined in models.py

from django.contrib.auth.password_validation import validate_password
# This allows passwords to have the basic django password validations
# i.e. password cannot be alphabets only, it needs to have numbers
# or special characters, it cannot be too similar to username, etc.


class RegisterSerializer(serializers.ModelSerializer):

    '''This code defines a serializer for registering new users.
    It validates and creates a new user instance with the provided data
    Including a password that meets Django's password validation rules.
    The create method sets the password securely using set_password and
    saves the user instance.'''

    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password])

    class Meta:
        model = User
        fields = ('username', 'password', 'email',
                  'first_name', 'last_name', 'role')

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            # Default to EMPLOYEE
            role=validated_data.get('role', User.Role.EMPLOYEE),
        )
        user.set_password(validated_data['password'])
        user.save()
        return user


class UserSerializer(serializers.ModelSerializer):

    '''
    This code defines a serializer for updating a User instance.
    (when you login, etc.) The serializer includes the following fields: 
        id, username, email, first_name, last_name, role, and password.

    The password field is write-only, meaning it will be excluded
    from the serialized output, and is not required for updates.

    The update method updates the user instance with the provided
    data, handling the password separately by using the set_password
    method to securely store the new password.
    '''
    password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = ('id', 'username', 'email',
                  'first_name', 'last_name', 'role', 'password')

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password:
            instance.set_password(password)
        instance.save()
        return instance
