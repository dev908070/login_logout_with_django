from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from django.contrib.auth import get_user_model
from .models import EmailConfirmation
from .serializers import UserSerializer, EmailConfirmationSerializer
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings
from .models import EmailConfirmation
from django.contrib.auth import authenticate, login
from rest_framework_simplejwt.tokens import RefreshToken
from .models import CustomUser



User = get_user_model()

@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request):
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        user.set_password(user.password)
        user.save()
        print(f"User registered: {user.email}")
        print(f"Database Password: {user.password}")
        try:
            email_confirmation = EmailConfirmation.objects.create(user=user, token=user.email)
            email_confirmation.save()
        except Exception as e:
            print(f"Error creating EmailConfirmation: {e}")
            return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Send confirmation email
        subject = 'Confirm your email'
        html_message = render_to_string('confirmation_email.html', {'confirmation_link': f"http://127.0.0.1:8000/api/confirm/{email_confirmation.token}/"})
        plain_message = strip_tags(html_message)
        from_email = settings.EMAIL_HOST_USER
        to_email = [user.email]

        send_mail(subject, plain_message, from_email, to_email, html_message=html_message)

        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def confirm_email(request, token):
    try:
        email_confirmation = EmailConfirmation.objects.get(token=token)
    except EmailConfirmation.DoesNotExist:
        return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

    user = email_confirmation.user
    user.is_active = True
    user.save()
    email_confirmation.delete()
    return Response({'message': 'Email confirmed successfully'}, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([AllowAny])
def login_user(request):
    email = request.data.get('email')
    password = request.data.get('password')
    print(f"Email: {email}, Password: {password}")
    user = CustomUser.objects.filter(email=email).first()  
    if user is not None and user.check_password(password):
        if user.is_active:
            login(request, user)
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            return Response({'message': 'Login successful', 'user_id': user.id, 'access_token': access_token})
        else:
            return Response({'error': 'Your account is not activated please check your email'}, status=status.HTTP_401_UNAUTHORIZED)
    else:
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
