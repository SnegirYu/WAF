# /waf_admin/WAF/accounts/signals.py
import sys
from datetime import datetime
from django.contrib.auth.signals import user_login_failed
from django.dispatch import receiver

# Путь к файлу лога, который будет читать fail2ban
# Вы можете изменить его на тот, который используете
FAIL2BAN_LOG = '/app/logs/fail2ban.log'
@receiver(user_login_failed)
def log_failed_login(sender, credentials, request, **kwargs):
    """
    Логирует неудачные попытки входа для fail2ban.
    """
    # Получаем имя пользователя из данных формы
    username = credentials.get('username', 'unknown')

    # Безопасно получаем IP-адрес клиента, учитывая прокси
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        client_ip = x_forwarded_for.split(',')[0].strip()
    else:
        client_ip = request.META.get('REMOTE_ADDR', 'unknown')

    # Формируем строку лога
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_line = f"{timestamp} [fail2ban] Failed login attempt: {client_ip} | user: {username}\n"

    # Пишем в stderr, чтобы попало в docker logs
    sys.stderr.write(log_line)
    sys.stderr.flush()

    # Пишем в файл для fail2ban
    try:
        with open(FAIL2BAN_LOG, 'a') as f:
            f.write(log_line)
    except Exception as e:
        # Игнорируем ошибки записи, чтобы не нарушить работу входа
        print(f"Failed to write to {FAIL2BAN_LOG}: {e}", file=sys.stderr)
