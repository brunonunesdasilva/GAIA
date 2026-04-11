import os
import django

# Ajuste 'gaia.settings' para o nome correto da sua pasta de configurações
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from django.contrib.auth import get_user_model

User = get_user_model()

def env_flag(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


if not env_flag("CREATE_SUPERUSER", "false"):
    print("CREATE_SUPERUSER desativado. Nada a fazer.")
    raise SystemExit(0)

username = os.getenv("DJANGO_SUPERUSER_USERNAME", "").strip()
email = os.getenv("DJANGO_SUPERUSER_EMAIL", "").strip()
password = os.getenv("DJANGO_SUPERUSER_PASSWORD", "").strip()
cpf = os.getenv("DJANGO_SUPERUSER_CPF", "").strip()
first_name = os.getenv("DJANGO_SUPERUSER_FIRST_NAME", "Admin").strip()

missing = [
    key
    for key, value in [
        ("DJANGO_SUPERUSER_USERNAME", username),
        ("DJANGO_SUPERUSER_EMAIL", email),
        ("DJANGO_SUPERUSER_PASSWORD", password),
        ("DJANGO_SUPERUSER_CPF", cpf),
    ]
    if not value
]

if missing:
    print("Variaveis obrigatorias ausentes: " + ", ".join(missing))
    raise SystemExit(1)

if User.objects.filter(cpf=cpf).exists() or User.objects.filter(username=username).exists():
    print(f"Superusuario ja existe (username={username}, cpf={cpf}).")
else:
    User.objects.create_superuser(
        username=username,
        email=email,
        password=password,
        cpf=cpf,
        first_name=first_name,
    )
    print(f"Superusuario {username} criado com sucesso!")