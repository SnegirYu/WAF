from django import forms

class RegistrationForm(forms.Form):
    username = forms.CharField(max_length=100, label="Логин")
    email = forms.EmailField(label="Email")
    password = forms.CharField(widget=forms.PasswordInput, label="Пароль")