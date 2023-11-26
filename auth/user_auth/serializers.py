from rest_framework import serializers
from .models import CustomUser, EmailConfirmation

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('id', 'email', 'is_active','password')
        extra_kwargs = {'password': {'write_only': True}}
    

class EmailConfirmationSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmailConfirmation
        fields = ('token',)
