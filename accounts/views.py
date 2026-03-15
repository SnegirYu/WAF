from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
import uuid
from .forms import RegistrationForm
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.conf import settings

User = get_user_model()

def verify_email(request, token):
    try:
        user = User.objects.get(email_verification_token=token)
        user.is_active = True
        user.is_email_verified = True
        user.email_verification_token = None
        user.save()
        return render(request, 'accounts/verify_success.html')
    except User.DoesNotExist:
        return render(request, 'accounts/error.html', {'message': 'Неверный токен'})

def register_view(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = User.objects.create_user(
                username=form.cleaned_data['username'],
                email=form.cleaned_data['email'],
                password=form.cleaned_data['password']
            )
            user.is_active = False 
            user.email_verification_token = str(uuid.uuid4())
            user.save()

            verify_url = f"http://127.0.0.1:8000/verify/{user.email_verification_token}/"

            subject = "Подтверждение регистрации в WAF"
            message = f"Здравствуйте! Для активации вашего аккаунта перейдите по ссылке: {verify_url}"

            send_mail(
                subject,
                message,
                settings.EMAIL_HOST_USER,
                [user.email],
                fail_silently=False,
            )
            return render(request, 'accounts/verify_sent.html', {'email': form.cleaned_data['email']})
    else:
        form = RegistrationForm()
    return render(request, 'accounts/register.html', {'form': form})

@login_required
def dashboard_view(request):
    return render(request, 'accounts/dashboard.html', {'user': request.user})
