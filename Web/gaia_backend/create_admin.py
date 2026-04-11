import os
import django

# Ajuste 'gaia.settings' para o nome correto da sua pasta de configurações
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from django.contrib.auth import get_user_model

User = get_user_model()

# Defina os dados do seu admin aqui
username = "admin"
email = "admin@gmail.com"
password = "senha134"
cpf = "12345678901"
first_name = "Admin"

if not User.objects.filter(username=username).exists():
    User.objects.create_superuser(
        username=username,
        email=email,
        password=password,
        cpf=cpf,
        first_name=first_name
    )
    print(f"Superusuario {username} criado com sucesso!")
else:
    print(f"Usuario {username} ja existe.")