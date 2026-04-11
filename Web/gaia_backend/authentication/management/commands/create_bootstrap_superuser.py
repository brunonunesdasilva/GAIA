import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Create bootstrap superuser from environment variables (idempotent)."

    def handle(self, *args, **options):
        create_flag = os.getenv("CREATE_SUPERUSER", "false").strip().lower()
        if create_flag not in {"1", "true", "yes", "on"}:
            self.stdout.write(self.style.WARNING("CREATE_SUPERUSER is not enabled. Skipping."))
            return

        cpf = os.getenv("DJANGO_SUPERUSER_CPF", "").strip()
        username = os.getenv("DJANGO_SUPERUSER_USERNAME", "").strip()
        email = os.getenv("DJANGO_SUPERUSER_EMAIL", "").strip()
        first_name = os.getenv("DJANGO_SUPERUSER_FIRST_NAME", "").strip()
        password = os.getenv("DJANGO_SUPERUSER_PASSWORD", "").strip()

        missing = [
            name
            for name, value in [
                ("DJANGO_SUPERUSER_CPF", cpf),
                ("DJANGO_SUPERUSER_USERNAME", username),
                ("DJANGO_SUPERUSER_EMAIL", email),
                ("DJANGO_SUPERUSER_FIRST_NAME", first_name),
                ("DJANGO_SUPERUSER_PASSWORD", password),
            ]
            if not value
        ]

        if missing:
            self.stdout.write(
                self.style.ERROR(
                    "Missing required env vars: " + ", ".join(missing)
                )
            )
            return

        User = get_user_model()

        if User.objects.filter(cpf=cpf).exists():
            self.stdout.write(self.style.WARNING(f"Superuser with CPF {cpf} already exists. Skipping."))
            return

        User.objects.create_superuser(
            cpf=cpf,
            username=username,
            email=email,
            first_name=first_name,
            password=password,
        )
        self.stdout.write(self.style.SUCCESS(f"Bootstrap superuser created: {cpf}"))
