from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth.hashers import make_password
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth import get_user_model
from django_ratelimit.decorators import ratelimit

from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.utils.crypto import get_random_string
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
import logging
from datetime import datetime, date, timedelta

from .models import Usuario, ConfiguracaoEmail
from .serializers import ConfiguracaoEmailSerializer, CustomTokenObtainPairSerializer

from rest_framework.permissions import IsAdminUser

from .security import (
    record_login_attempt,
    get_failed_attempts,
    get_login_security_status,
    should_block_login,
    create_captcha_challenge,
    verify_captcha,
    clear_failed_attempts
)

logger = logging.getLogger(__name__)

# ============ View customizada que retorna primeiro_acesso ============
class CustomTokenObtainPairView(TokenObtainPairView):
    """
    View customizada que estende TokenObtainPairView
    e usa CustomTokenObtainPairSerializer para incluir
    informações do usuário e campo primeiro_acesso
    """
    serializer_class = CustomTokenObtainPairSerializer

# ===============================================
#  LOGIN COM SEGURANÇA PROGRESSIVA + CAPTCHA
# ===============================================

@ratelimit(key='ip', rate='6/m', method='POST', block=True)
@api_view(['POST'])
@permission_classes([AllowAny])
def login_with_cpf_secure(request):
    """
    Login com segurança progressiva:
    - 0-2 falhas: Sem restrição
    - 3-4 falhas: Aguardar 30s entre tentativas
    - 5+ falhas: Requer CAPTCHA
    """
    cpf = request.data.get('cpf', '').replace('.', '').replace('-', '')
    password = request.data.get('password')
    captcha_token = request.data.get('captcha_token')  # Opcional
    captcha_answer = request.data.get('captcha_answer')  # Opcional
    ip_address = get_client_ip(request)
    
    if not cpf or not password:
        return Response(
            {'error': 'CPF e senha são obrigatórios'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    #  Verificar se está bloqueado completamente
    if should_block_login(cpf, ip_address):
        return Response(
            {'error': 'Muitas tentativas. Conta bloqueada temporariamente.'},
            status=status.HTTP_429_TOO_MANY_REQUESTS
        )
    
    #  Obter status de segurança
    security_status = get_login_security_status(cpf, ip_address)
    
    #  Se requer CAPTCHA, validar primeiro
    if security_status['require_captcha']:
        if not captcha_token or not captcha_answer:
            # Usuário não enviou CAPTCHA, gerar novo desafio
            captcha_data = create_captcha_challenge(cpf, ip_address)
            return Response({
                'require_captcha': True,
                'captcha': captcha_data,
                'message': 'Muito muitas tentativas. Por favor, resolva o CAPTCHA.'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Validar CAPTCHA
        captcha_valid, captcha_msg = verify_captcha(captcha_token, captcha_answer)
        if not captcha_valid:
            return Response({
                'require_captcha': True,
                'error': captcha_msg
            }, status=status.HTTP_403_FORBIDDEN)
    
    #  Tentar login
    User = get_user_model()
    
    try:
        user = User.objects.get(cpf=cpf)
        
        if user.check_password(password):
            if user.is_active:
                #  Login bem-sucedido
                record_login_attempt(cpf, ip_address, success=True)
                clear_failed_attempts(cpf, ip_address)
                
                # Gerar tokens
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                refresh_token = str(refresh)
                
                response = Response({
                    'user': {
                        'id': user.id,
                        'nome': f'{user.first_name} {user.last_name}'.strip(),
                        'email': user.email,
                        'cpf': cpf,
                        'is_staff': user.is_staff,
                        'primeiro_acesso': user.primeiro_acesso,
                    }
                }, status=status.HTTP_200_OK)
                
                # Configurar cookies
                response.set_cookie(
                    key='access_token',
                    value=access_token,
                    httponly=True,
                    secure=not settings.DEBUG,
                    samesite='None' if not settings.DEBUG else 'Lax',
                    max_age=3600,
                    path='/'
                )
                response.set_cookie(
                    key='refresh_token',
                    value=refresh_token,
                    httponly=True,
                    secure=not settings.DEBUG,
                    samesite='None' if not settings.DEBUG else 'Lax',
                    max_age=7 * 24 * 3600,
                    path='/'
                )
                
                return response
        
        #  Senha incorreta
        failed = get_failed_attempts(cpf, ip_address, minutes=60)
        record_login_attempt(cpf, ip_address, success=False)
        
        # Checar se agora precisa de CAPTCHA
        new_security_status = get_login_security_status(cpf, ip_address)
        
        if new_security_status['require_captcha']:
            captcha_data = create_captcha_challenge(cpf, ip_address)
            return Response({
                'error': 'Credenciais inválidas',
                'require_captcha': True,
                'captcha': captcha_data,
                'failed_attempts': new_security_status['failed_attempts']
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        return Response({
            'error': 'Credenciais inválidas',
            'failed_attempts': failed,
            'max_attempts_before_captcha': 5
        }, status=status.HTTP_401_UNAUTHORIZED)
        
    except User.DoesNotExist:
        record_login_attempt(cpf, ip_address, success=False)
        return Response(
            {'error': 'Credenciais inválidas'},
            status=status.HTTP_401_UNAUTHORIZED
        )
    except Exception as e:
        logger.exception('Erro interno no login CPF seguro')
        return Response(
            {'error': 'Erro interno do servidor'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@ratelimit(key='ip', rate='6/m', method='POST', block=True)
@api_view(['POST'])
@permission_classes([AllowAny])
def login_with_cnpj_secure(request):
    """
    Login com segurança progressiva:
    - 0-2 falhas: Sem restrição
    - 3-4 falhas: Aguardar 30s entre tentativas
    - 5+ falhas: Requer CAPTCHA
    """
    cnpj = request.data.get('cnpj', '').replace('.', '').replace('-', '').replace('/', '')
    password = request.data.get('password')
    captcha_token = request.data.get('captcha_token')  # Opcional
    captcha_answer = request.data.get('captcha_answer')  # Opcional
    ip_address = get_client_ip(request)
    
    if not cnpj or not password:
        return Response(
            {'error': 'CNPJ e senha são obrigatórios'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    #  Verificar se está bloqueado completamente
    if should_block_login(cnpj, ip_address):
        return Response(
            {'error': 'Muitas tentativas. Conta bloqueada temporariamente.'},
            status=status.HTTP_429_TOO_MANY_REQUESTS
        )
    
    #  Obter status de segurança
    security_status = get_login_security_status(cnpj, ip_address)
    
    #  Se requer CAPTCHA, validar primeiro
    if security_status['require_captcha']:
        if not captcha_token or not captcha_answer:
            # Usuário não enviou CAPTCHA, gerar novo desafio
            captcha_data = create_captcha_challenge(cnpj, ip_address)
            return Response({
                'require_captcha': True,
                'captcha': captcha_data,
                'message': 'Muito muitas tentativas. Por favor, resolva o CAPTCHA.'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Validar CAPTCHA
        captcha_valid, captcha_msg = verify_captcha(captcha_token, captcha_answer)
        if not captcha_valid:
            return Response({
                'require_captcha': True,
                'error': captcha_msg
            }, status=status.HTTP_403_FORBIDDEN)
    
    #  Tentar login
    User = get_user_model()
    
    try:
        user = User.objects.get(cnpj=cnpj)
        
        if user.check_password(password):
            if user.is_active:
                #  Login bem-sucedido
                record_login_attempt(cnpj, ip_address, success=True)
                clear_failed_attempts(cnpj, ip_address)
                
                # Gerar tokens
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                refresh_token = str(refresh)
                
                response = Response({
                    'user': {
                        'id': user.id,
                        'nome': f'{user.first_name} {user.last_name}'.strip(),
                        'email': user.email,
                        'cnpj': cnpj,
                        'is_staff': user.is_staff,
                        'primeiro_acesso': user.primeiro_acesso,
                    }
                }, status=status.HTTP_200_OK)
                
                # Configurar cookies
                response.set_cookie(
                    key='access_token',
                    value=access_token,
                    httponly=True,
                    secure=not settings.DEBUG,
                    samesite='None' if not settings.DEBUG else 'Lax',
                    max_age=3600,
                    path='/'
                )
                response.set_cookie(
                    key='refresh_token',
                    value=refresh_token,
                    httponly=True,
                    secure=not settings.DEBUG,
                    samesite='None' if not settings.DEBUG else 'Lax',
                    max_age=7 * 24 * 3600,
                    path='/'
                )
                
                return response
        
        #  Senha incorreta
        failed = get_failed_attempts(cnpj, ip_address, minutes=60)
        record_login_attempt(cnpj, ip_address, success=False)
        
        # Checar se agora precisa de CAPTCHA
        new_security_status = get_login_security_status(cnpj, ip_address)
        
        if new_security_status['require_captcha']:
            captcha_data = create_captcha_challenge(cnpj, ip_address)
            return Response({
                'error': 'Credenciais inválidas',
                'require_captcha': True,
                'captcha': captcha_data,
                'failed_attempts': new_security_status['failed_attempts']
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        return Response({
            'error': 'Credenciais inválidas',
            'failed_attempts': failed,
            'max_attempts_before_captcha': 5
        }, status=status.HTTP_401_UNAUTHORIZED)
        
    except User.DoesNotExist:
        record_login_attempt(cnpj, ip_address, success=False)
        return Response(
            {'error': 'Credenciais inválidas'},
            status=status.HTTP_401_UNAUTHORIZED
        )
    except Exception as e:
        logger.exception('Erro interno no login CNPJ seguro')
        return Response(
            {'error': 'Erro interno do servidor'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def verify_captcha_endpoint(request):
    """Endpoint para verificar resposta de CAPTCHA"""
    token = request.data.get('captcha_token')
    answer = request.data.get('captcha_answer')
    
    if not token or not answer:
        return Response(
            {'error': 'Token e resposta são obrigatórios'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    valid, message = verify_captcha(token, answer)
    
    if valid:
        return Response({
            'success': True,
            'message': message
        }, status=status.HTTP_200_OK)
    else:
        return Response({
            'success': False,
            'error': message
        }, status=status.HTTP_403_FORBIDDEN)


# ===============================================
#  LOGIN DESKTOP - Retorna token no JSON
# ===============================================

# Rate limit para desktop: controla por CPF enviado para evitar bloqueio global por IP compartilhado.
# block=False para permitir bypass controlado de admins desktop sem remover proteção dos demais.
@ratelimit(key='post:cpf', rate='30/h', method='POST', block=False)
@api_view(['POST'])
@permission_classes([AllowAny])
def login_with_cpf_desktop(request):
    """
    Login simplificado para aplicação desktop.
    Retorna access_token e refresh_token no corpo da resposta JSON.
    
    ATENÇÃO: Este endpoint retorna tokens no JSON body (não em cookies).
    Use apenas para aplicações desktop/CLI onde cookies não são apropriados.
    Para web, use /login/cpf/secure/ que usa httpOnly cookies.
    """
    cpf = request.data.get('cpf', '').replace('.', '').replace('-', '').strip()
    password = request.data.get('password', '')
    
    if not cpf or not password:
        return Response(
            {'error': 'CPF e senha são obrigatórios'},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Se atingiu ratelimit, permite bypass apenas para admins ativos.
    if getattr(request, 'limited', False):
        usuario_rate = Usuario.objects.filter(cpf=cpf).first()
        if not (usuario_rate and usuario_rate.is_staff and usuario_rate.is_active):
            return Response(
                {'error': 'Muitas tentativas de login. Aguarde alguns minutos.'},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )
        logger.info('Bypass de ratelimit aplicado para admin no login desktop cpf=%s', cpf)
    
    # Obter IP para rate limiting
    ip_address = request.META.get('REMOTE_ADDR', 'unknown')
    
    # Verificar bloqueio por tentativas excessivas (proteção básica)
    if should_block_login(cpf, ip_address):
        return Response({
            'error': 'Muitas tentativas de login. Aguarde 30 minutos.'
        }, status=status.HTTP_429_TOO_MANY_REQUESTS)
    
    User = get_user_model()
    
    try:
        user = User.objects.get(cpf=cpf)
        
        if user.check_password(password):
            if user.is_active:
                # Login bem-sucedido
                record_login_attempt(cpf, ip_address, success=True)
                clear_failed_attempts(cpf, ip_address)
                
                # Gerar tokens
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                refresh_token = str(refresh)
                
                logger.info('Login desktop bem-sucedido para usuario_id=%s', user.id)
                
                return Response({
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                    'user': {
                        'id': user.id,
                        'nome': f'{user.first_name} {user.last_name}'.strip(),
                        'email': user.email,
                        'cpf': cpf,
                        'is_staff': user.is_staff,
                        'primeiro_acesso': user.primeiro_acesso,
                    }
                }, status=status.HTTP_200_OK)
            else:
                return Response(
                    {'error': 'Conta desativada'},
                    status=status.HTTP_403_FORBIDDEN
                )
        
        # Senha incorreta
        record_login_attempt(cpf, ip_address, success=False)
        failed = get_failed_attempts(cpf, ip_address, minutes=60)
        
        return Response({
            'error': 'Credenciais inválidas',
            'failed_attempts': failed
        }, status=status.HTTP_401_UNAUTHORIZED)
        
    except User.DoesNotExist:
        record_login_attempt(cpf, ip_address, success=False)
        return Response(
            {'error': 'Credenciais inválidas'},
            status=status.HTTP_401_UNAUTHORIZED
        )
    except Exception as e:
        logger.exception('Erro interno no login desktop')
        return Response(
            {'error': 'Erro interno do servidor'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


def get_client_ip(request):
    """Extrai o IP real do cliente (considerando proxies)"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def validate_data_nascimento(data_nascimento_str):
    """
    Valida data de nascimento.
    
    Args:
        data_nascimento_str: String no formato 'YYYY-MM-DD', 'DD/MM/YYYY' ou objeto date
    
    Returns:
        tuple: (is_valid: bool, error_message: str, data_normalizada: date ou None)
    
    Validações:
    - Formato válido
    - Não pode ser futura
    - Idade mínima de 18 anos
    - Idade máxima razoável (120 anos)
    """
    if not data_nascimento_str:
        return True, None, None  # Campo opcional
    
    # Se já é objeto date, usar diretamente
    if isinstance(data_nascimento_str, date):
        data_nascimento = data_nascimento_str
    else:
        # Tentar parsear de diferentes formatos
        try:
            # Tentar formato ISO: YYYY-MM-DD
            if '-' in str(data_nascimento_str):
                data_nascimento = datetime.strptime(str(data_nascimento_str), '%Y-%m-%d').date()
            # Tentar formato brasileiro: DD/MM/YYYY
            elif '/' in str(data_nascimento_str):
                data_nascimento = datetime.strptime(str(data_nascimento_str), '%d/%m/%Y').date()
            else:
                return False, 'Formato de data inválido. Use YYYY-MM-DD ou DD/MM/YYYY', None
        except (ValueError, TypeError):
            return False, 'Data de nascimento inválida. Use formato YYYY-MM-DD ou DD/MM/YYYY', None
    
    hoje = date.today()
    
    # Verificar se a data não é futura
    if data_nascimento > hoje:
        return False, 'Data de nascimento não pode ser futura', None
    
    # Calcular idade
    idade = hoje.year - data_nascimento.year - ((hoje.month, hoje.day) < (data_nascimento.month, data_nascimento.day))
    
    # Verificar idade mínima (18 anos)
    if idade < 18:
        return False, f'Idade mínima é 18 anos. Idade atual: {idade} anos', None
    
    # Verificar idade máxima razoável (120 anos)
    if idade > 120:
        return False, f'Data de nascimento muito antiga. Idade calculada: {idade} anos', None
    
    # Validação adicional: ano não pode ser anterior a 1900
    if data_nascimento.year < 1900:
        return False, 'Ano de nascimento não pode ser anterior a 1900', None
    
    return True, None, data_nascimento


# Endpoint de Logout (limpa httpOnly cookies)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    """Logout - Remove os httpOnly cookies de autenticação"""
    response = Response(
        {'message': 'Logout realizado com sucesso'},
        status=status.HTTP_200_OK
    )
    
    # Remove os cookies de autenticação
    response.delete_cookie('access_token')
    response.delete_cookie('refresh_token')
    
    return response

# Endpoint de Refresh Token (renova access_token usando refresh_token do cookie)
@api_view(['POST'])
@permission_classes([AllowAny])
def refresh_token_from_cookie(request):
    """Refresh token - Renova o access_token usando refresh_token do cookie"""
    try:
        refresh_token = request.COOKIES.get('refresh_token')
        
        if not refresh_token:
            return Response(
                {'error': 'Refresh token não encontrado'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        try:
            refresh = RefreshToken(refresh_token)
            new_access = str(refresh.access_token)
            new_refresh = str(refresh)
            
            response = Response(
                {
                    'message': 'Token renovado com sucesso'
                },
                status=status.HTTP_200_OK
            )
            
            # Atualizar cookies com novo access_token
            response.set_cookie(
                key='access_token',
                value=new_access,
                httponly=True,
                secure=not settings.DEBUG,
                samesite='None' if not settings.DEBUG else 'Lax',
                max_age=3600,
                path='/'
            )
            response.set_cookie(
                key='refresh_token',
                value=new_refresh,
                httponly=True,
                secure=not settings.DEBUG,
                samesite='None' if not settings.DEBUG else 'Lax',
                max_age=7 * 24 * 3600,
                path='/'
            )
            
            return response
            
        except Exception as e:
            return Response(
                {'error': 'Token inválido ou expirado'},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
    except Exception as e:
        logger.exception('Erro ao renovar token via cookie')
        return Response({'error': 'Erro interno do servidor'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# 1. Cadastro de Cliente com Envio de Senha
@api_view(['POST'])
@permission_classes([IsAdminUser])
def register_client_email(request):
    """
    Cadastra o usuário, gera uma senha aleatória e envia por e-mail.
    """
    data = request.data
    email = data.get('email')
    cpf = data.get('cpf')
    nome = data.get('first_name')

    if not email or not cpf:
        return Response({'error': 'Email e CPF são obrigatórios.'}, status=status.HTTP_400_BAD_REQUEST)

    if Usuario.objects.filter(cpf=cpf).exists():
        return Response({'error': 'CPF já cadastrado.'}, status=status.HTTP_400_BAD_REQUEST)
    
    if Usuario.objects.filter(email=email).exists():
        return Response({'error': 'Email já cadastrado.'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Verificar se email existe em Person ou Empresa (cross-table validation)
    from report.models import Person, Empresa
    if Person.objects.filter(email=email).exists():
        return Response({'error': 'Email já cadastrado para outra pessoa.'}, status=status.HTTP_400_BAD_REQUEST)
    if Empresa.objects.filter(email=email).exists():
        return Response({'error': 'Email já cadastrado para uma empresa.'}, status=status.HTTP_400_BAD_REQUEST)

    # Validar data de nascimento (se fornecida)
    data_nascimento = data.get('data_nascimento')
    if data_nascimento:
        is_valid, error_msg, data_normalizada = validate_data_nascimento(data_nascimento)
        if not is_valid:
            return Response({'error': error_msg}, status=status.HTTP_400_BAD_REQUEST)
        data_nascimento = data_normalizada

    try:
        # Gera uma senha aleatória
        temp_password = get_random_string(length=12)

        # Cria o usuário
        user = Usuario.objects.create(
            username=cpf, # Mantemos CPF como username interno
            cpf=cpf,
            email=email,
            first_name=nome,
            last_name=data.get('last_name', ''),
            telefone=data.get('phone_number', '') or data.get('telefone', ''),  # ← Adiciona telefone!
            data_nascimento=data_nascimento,  # ← Adiciona data de nascimento validada!
            primeiro_acesso=True # Marca para trocar a senha depois
        )
        user.set_password(temp_password)
        user.save()
        # Senha gerada com sucesso (não registrar em logs por segurança)

        # 1. Pega o template do banco (ou cria se não existir)
        config_email, _ = ConfiguracaoEmail.objects.get_or_create(id=1)
        
        assunto_email = config_email.assunto
        mensagem_template = config_email.mensagem

        # 2. Substitui os placeholders ({nome}, {senha}, {tipo_documento}) pelos dados reais
        # Usamos .format() de forma segura. Se o ADM apagou a tag {senha}, o Python não quebra, mas a senha não vai.
        try:
            mensagem_final = mensagem_template.format(
                nome=nome,
                senha=temp_password,
                email=email,
                tipo_documento="CPF"  # ← PESSOA FÍSICA = CPF
            )
        except KeyError:
            # Fallback: Se o ADM bagunçou as tags (ex: colocou {telefone} que não existe),
            # voltamos para um texto simples para garantir o envio.
            mensagem_final = f"Olá {nome}, sua senha temporária é: {temp_password}"

        # 3. Envia
        send_mail(
            assunto_email,
            mensagem_final,
            settings.DEFAULT_FROM_EMAIL if hasattr(settings, 'DEFAULT_FROM_EMAIL') else 'admin@gaia.com',
            [email],
            fail_silently=False,
        )

        return Response(
            {
                'message': 'Usuário criado e e-mail enviado.',
                'id': user.id,
            },
            status=status.HTTP_201_CREATED,
        )

    except Exception as e:
        logger.exception('Erro ao registrar cliente por email')
        return Response({'error': 'Erro interno do servidor'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Cadastro de Empresa com Envio de Senha
@api_view(['POST'])
@permission_classes([IsAdminUser])
def register_company_email(request):
    """
    Cadastra uma empresa, gera uma senha aleatória e envia por e-mail.
    """
    data = request.data
    email = data.get('email')
    cnpj = data.get('cnpj')
    nome = data.get('first_name')

    if not email or not cnpj:
        return Response({'error': 'Email e CNPJ são obrigatórios.'}, status=status.HTTP_400_BAD_REQUEST)

    # Limpar CNPJ
    cnpj_limpo = cnpj.replace('.', '').replace('/', '').replace('-', '')

    if Usuario.objects.filter(cnpj=cnpj_limpo).exists():
        return Response({'error': 'CNPJ já cadastrado.'}, status=status.HTTP_400_BAD_REQUEST)
    
    if Usuario.objects.filter(email=email).exists():
        return Response({'error': 'Email já cadastrado.'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Verificar se email existe em Person ou Empresa (cross-table validation)
    from report.models import Person, Empresa
    if Person.objects.filter(email=email).exists():
        return Response({'error': 'Email já cadastrado para uma pessoa.'}, status=status.HTTP_400_BAD_REQUEST)
    if Empresa.objects.filter(email=email).exists():
        return Response({'error': 'Email já cadastrado para outra empresa.'}, status=status.HTTP_400_BAD_REQUEST)

    # Validar data de nascimento (se fornecida - pode ser do representante legal)
    data_nascimento = data.get('data_nascimento')
    if data_nascimento:
        is_valid, error_msg, data_normalizada = validate_data_nascimento(data_nascimento)
        if not is_valid:
            return Response({'error': error_msg}, status=status.HTTP_400_BAD_REQUEST)
        data_nascimento = data_normalizada

    try:
        # Gera uma senha aleatória
        temp_password = get_random_string(length=12)
        # Senha gerada com sucesso (não registrar em logs por segurança)

        # Cria o usuário com CNPJ
        user = Usuario.objects.create(
            username=cnpj_limpo,  # CNPJ como username interno
            cnpj=cnpj_limpo,
            email=email,
            first_name=nome,
            last_name=data.get('last_name', ''),
            telefone=data.get('phone_number', '') or data.get('telefone', ''),  # ← Adiciona telefone!
            data_nascimento=data_nascimento,  # ← Adiciona data de nascimento validada!
            primeiro_acesso=True  # Marca para trocar a senha depois
        )
        user.set_password(temp_password)
        user.save()

        # 1. Pega o template do banco (ou cria se não existir)
        config_email, _ = ConfiguracaoEmail.objects.get_or_create(id=1)
        
        assunto_email = config_email.assunto
        mensagem_template = config_email.mensagem

        # 2. Substitui os placeholders pelos dados reais
        try:
            mensagem_final = mensagem_template.format(
                nome=nome,
                senha=temp_password,
                email=email,
                tipo_documento="CNPJ"  # ← PESSOA JURÍDICA = CNPJ
            )
        except KeyError as e:
            # Fallback: template com placeholder desconhecido
            logger.warning('Placeholder desconhecido no template de email de empresa: %s', e)
            mensagem_final = f"""Olá {nome},

Seu cadastro no sistema GAIA foi realizado com sucesso.

Login: Seu CNPJ
Senha Temporária: {temp_password}

Por favor, altere sua senha no primeiro acesso.

Em caso de dúvidas, entre em contato com nosso suporte (46) 999XX-XXXX."""

        # 3. Envia
        num_sent = send_mail(
            assunto_email,
            mensagem_final,
            settings.DEFAULT_FROM_EMAIL if hasattr(settings, 'DEFAULT_FROM_EMAIL') else 'admin@gaia.com',
            [email],
            fail_silently=False,
        )

        return Response(
            {
                'message': 'Empresa cadastrada e e-mail enviado.',
                'id': user.id,
            },
            status=status.HTTP_201_CREATED,
        )

    except Exception as e:
        logger.exception('Erro ao registrar empresa por email')
        return Response({'error': 'Erro interno do servidor'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    """
    Permite ao usuário logado alterar sua senha.
    Remove a flag de 'primeiro_acesso'.
    """
    try:
        user = request.user
        
        if not user.is_authenticated:
            return Response({'error': 'Usuário não autenticado.'}, status=status.HTTP_401_UNAUTHORIZED)
            
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')

        if not new_password:
            return Response({'error': 'Nova senha é obrigatória.'}, status=status.HTTP_400_BAD_REQUEST)

        if not old_password:
            return Response({'error': 'Senha atual é obrigatória.'}, status=status.HTTP_400_BAD_REQUEST)

        # Validar força da nova senha
        try:
            validate_password(new_password, user=user)
        except ValidationError as e:
            # Formatar mensagens de validação de senha para serem mais específicas
            error_messages = []
            
            for message in e.messages:
                message_str = str(message)
                
                # Traduzir e melhorar mensagens específicas do Django
                if 'too short' in message_str.lower() or 'must contain at least' in message_str.lower():
                    error_messages.append(' Senha muito curta - deve ter pelo menos 8 caracteres')
                elif 'entirely numeric' in message_str.lower():
                    error_messages.append(' Senha não pode conter apenas números')
                elif 'too similar' in message_str.lower():
                    error_messages.append(' Senha é muito similar ao nome de usuário ou email')
                elif 'common password' in message_str.lower():
                    error_messages.append(' Senha é muito comum - escolha uma senha mais segura (ex: MinhaSe9ha!)')
                else:
                    # Se não for mensagem conhecida, incluir a mensagem original
                    error_messages.append(f' {message_str}')
            
            return Response({
                'error': 'Senha fraca - não atende aos requisitos de segurança',
                'motivos': error_messages,
                'requisitos': [
                    'Mínimo 8 caracteres',
                    'Não pode ser apenas números',
                    'Não pode ser similar ao nome de usuário',
                    'Não pode ser uma senha comum (ex: 12345678, password)'
                ]
            }, status=status.HTTP_400_BAD_REQUEST)

        # Verifica a senha antiga
        is_password_correct = user.check_password(old_password)
        
        if not is_password_correct:
            return Response({'error': 'Senha atual incorreta.'}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.primeiro_acesso = False
        user.save()

        return Response({'message': 'Senha alterada com sucesso.'}, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.exception('Erro ao alterar senha')
        return Response({'error': 'Erro interno do servidor'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@ratelimit(key='ip', rate='5/h', method='POST', block=True)
@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password(request):
    email = request.data.get('email')
    if not email:
        return Response({'message': 'Se o e-mail estiver cadastrado, você receberá instruções de recuperação.'}, status=status.HTTP_200_OK)

    try:
        user = Usuario.objects.get(email=email)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        frontend_base = settings.FRONTEND_URL
        reset_link = f"{frontend_base.rstrip('/')}/reset-password?uid={uid}&token={token}"

        subject = 'Recuperação de Senha - GAIA'
        message = f"""Olá {user.first_name},

Recebemos uma solicitação para redefinir sua senha.

Use este link para criar uma nova senha:
{reset_link}

Se você não solicitou esta alteração, ignore este e-mail.
"""

        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL if hasattr(settings, 'DEFAULT_FROM_EMAIL') else 'admin@gaia.com',
            [email],
            fail_silently=False,
        )
    except Usuario.DoesNotExist:
        pass
    except Exception as e:
        logger.exception('Erro no fluxo de recuperação de senha')

    return Response({'message': 'Se o e-mail estiver cadastrado, você receberá instruções de recuperação.'}, status=status.HTTP_200_OK)


@ratelimit(key='ip', rate='10/h', method='POST', block=True)
@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password_with_token(request):
    """Redefine senha usando uid/token enviados por e-mail."""
    uidb64 = request.data.get('uid')
    token = request.data.get('token')
    new_password = request.data.get('new_password')

    if not uidb64 or not token or not new_password:
        return Response({'error': 'uid, token e new_password são obrigatórios.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = Usuario.objects.get(pk=uid)
    except Exception:
        return Response({'error': 'Token inválido ou expirado.'}, status=status.HTTP_400_BAD_REQUEST)

    if not default_token_generator.check_token(user, token):
        return Response({'error': 'Token inválido ou expirado.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        validate_password(new_password, user=user)
    except ValidationError as e:
        return Response({'error': 'Senha fraca', 'motivos': e.messages}, status=status.HTTP_400_BAD_REQUEST)

    user.set_password(new_password)
    user.primeiro_acesso = False
    user.save()

    return Response({'message': 'Senha redefinida com sucesso.'}, status=status.HTTP_200_OK)


@api_view(['GET', 'POST'])
@permission_classes([IsAdminUser]) 
def manage_email_template(request):
    """
    GET: Retorna o template atual.
    POST: Atualiza o template.
    """
    # Tenta pegar a configuração existente, se não existir, cria uma padrão
    config, created = ConfiguracaoEmail.objects.get_or_create(id=1)

    if request.method == 'GET':
        serializer = ConfiguracaoEmailSerializer(config)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = ConfiguracaoEmailSerializer(config, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Template de e-mail atualizado com sucesso!', 'data': serializer.data})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAdminUser])
def sync_usuario(request):
    """API simples para o software cadastrar usuários - Apenas admins"""
    logger.info('sync_usuario solicitado por usuario_id=%s', request.user.id)
    
    try:
        data = request.data
        
        # Validar CPF (obrigatório)
        cpf = data.get('cpf', '').strip()
        if not cpf:
            return Response(
                {'error': 'CPF é obrigatório'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validar email (obrigatório e único)
        email = data.get('email', '').strip()
        if not email:
            return Response(
                {'error': 'Email é obrigatório'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validar formato básico de email
        if '@' not in email or '.' not in email:
            return Response(
                {'error': f'Email "{email}" é inválido'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Verificar se CPF já existe
        if Usuario.objects.filter(cpf=cpf).exists():
            user = Usuario.objects.get(cpf=cpf)
            user_id = user.id
            return Response({
                'error': f"CPF {cpf} já está cadastrado no sistema (ID: {user_id})",
                'status': 'cpf_exists',
                'id': user_id,
            }, status=status.HTTP_409_CONFLICT)
        
        # Verificar se email já existe
        if Usuario.objects.filter(email=email).exists():
            existing_user = Usuario.objects.get(email=email)
            return Response({
                'error': f'Email "{email}" já está cadastrado. Use outro email!',
                'status': 'email_exists',
                'id': existing_user.id,
            }, status=status.HTTP_409_CONFLICT)
        
        # Cria novo usuário
        first_name = data.get('first_name', '').strip()
        if not first_name:
            return Response(
                {'error': 'Nome é obrigatório'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validar data de nascimento (se fornecida)
        data_nascimento = data.get('data_nascimento')
        if data_nascimento:
            is_valid, error_msg, data_normalizada = validate_data_nascimento(data_nascimento)
            if not is_valid:
                return Response({'error': error_msg}, status=status.HTTP_400_BAD_REQUEST)
            data_nascimento = data_normalizada
        
        usuario = Usuario.objects.create(
            username=cpf,  # Usa CPF como username
            cpf=cpf,
            first_name=first_name,
            last_name=data.get('last_name', '').strip(),
            email=email,  # Email único
            telefone=data.get('phone_number', '').strip(),
            data_nascimento=data_nascimento,  # ← Adiciona data de nascimento validada!
            password=make_password(data.get('password', '123456'))
        )

        logger.info('sync_usuario criou usuario_id=%s', usuario.id)
        return Response({
            'id': usuario.id,
            'status': 'created',
            'message': 'Usuário criado com sucesso',
            'cpf': usuario.cpf,
            'email': usuario.email,
            'name': usuario.first_name
        }, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        logger.exception('Erro ao sincronizar criação de usuário')
        return Response({'error': 'Falha ao processar operação'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def list_usuarios(request):
    """Lista todos os usuários cadastrados via sync_usuario"""
    logger.info('list_usuarios solicitado por usuario_id=%s', request.user.id)
    
    try:
        # Filtros opcionais
        cpf_filter = request.query_params.get('cpf')
        name_filter = request.query_params.get('name')
        
        usuarios = Usuario.objects.all()
        
        # Aplicar filtros
        if cpf_filter:
            usuarios = usuarios.filter(cpf__icontains=cpf_filter)
        if name_filter:
            usuarios = usuarios.filter(first_name__icontains=name_filter)
        
        # Ordenar por ID descendente (mais recentes primeiro)
        usuarios = usuarios.order_by('-id')
        
        # Serializar
        data = []
        for user in usuarios:
            data.append({
                'id': user.id,
                'username': user.username,
                'name': f"{user.first_name} {user.last_name}".strip(),
                'first_name': user.first_name,
                'last_name': user.last_name,
                'cpf': user.cpf,
                'email': user.email,
                'telefone': getattr(user, 'telefone', ''),
                'is_staff': user.is_staff,
                'is_active': user.is_active,
                'data_criacao': user.date_joined.isoformat() if hasattr(user, 'date_joined') else None,
            })
        
        logger.info('list_usuarios retornou total=%s', len(data))
        return Response({
            'count': len(data),
            'results': data
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.exception('Erro ao listar usuários')
        return Response({'error': 'Falha ao processar operação'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['DELETE'])
@permission_classes([IsAdminUser])
def delete_usuario(request):
    """Exclui um usuario pelo CPF (apenas admins)."""
    cpf = request.query_params.get('cpf') or request.data.get('cpf')
    if not cpf:
        return Response({'error': 'CPF é obrigatório.'}, status=status.HTTP_400_BAD_REQUEST)

    cpf_limpo = cpf.replace('.', '').replace('-', '')

    try:
        user = Usuario.objects.get(cpf=cpf_limpo)
    except Usuario.DoesNotExist:
        return Response({'error': 'Usuário não encontrado.'}, status=status.HTTP_404_NOT_FOUND)

    # Remoção robusta: deleta Person/Empresa associadas e limpa Endereco órfão.
    # Isso também cobre registros antigos sem vínculo por usuario, usando CPF/CNPJ.
    from report.models import Person, Empresa, Endereco, Propriedade

    enderecos_candidatos = set()

    pessoa = Person.objects.filter(usuario=user).first() or Person.objects.filter(cpf=cpf_limpo).first()
    if pessoa and pessoa.endereco_id:
        enderecos_candidatos.add(pessoa.endereco_id)

    empresa = None
    if user.cnpj:
        cnpj_limpo = user.cnpj.replace('.', '').replace('/', '').replace('-', '')
        empresa = Empresa.objects.filter(usuario=user).first() or Empresa.objects.filter(cnpj=cnpj_limpo).first()
        if empresa and empresa.endereco_id:
            enderecos_candidatos.add(empresa.endereco_id)

    # Deletar entidades de domínio antes do usuário para preservar controle dos endereços
    if pessoa:
        pessoa.delete()
    if empresa:
        empresa.delete()

    user.delete()

    # Limpar endereços que ficaram sem referência
    enderecos_removidos = 0
    for endereco_id in enderecos_candidatos:
        if not Person.objects.filter(endereco_id=endereco_id).exists() \
           and not Empresa.objects.filter(endereco_id=endereco_id).exists() \
           and not Propriedade.objects.filter(endereco_id=endereco_id).exists():
            Endereco.objects.filter(id=endereco_id).delete()
            enderecos_removidos += 1

    return Response(
        {
            'message': 'Usuário excluído com sucesso.',
            'enderecos_removidos': enderecos_removidos,
        },
        status=status.HTTP_200_OK,
    )

User = get_user_model()

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def current_user(request):
    """Retorna informações do usuário logado, incluindo primeiro_acesso"""
    user = request.user
    
    return Response({'id': user.id,
                    'nome': f"{user.first_name} {user.last_name}",
                    'cpf': user.cpf,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'is_staff': user.is_staff,
                    'primeiro_acesso': user.primeiro_acesso
                    })

# ========== SINCRONIZAÇÃO DE DADOS EMPRESA/PERSON ↔ USUARIO ==========

@api_view(['PATCH'])
@permission_classes([IsAdminUser])
def sync_usuario_by_cpf(request):
    """
    Sincroniza dados do Usuario quando Person é editada
    PATCH /api/sync/usuario/cpf/
    Body: {
        "cpf": "123456789",
        "email": "novo@email.com",
        "first_name": "Nome Novo",
        "telefone": "11987654321"
    }
    """
    logger.info('sync_usuario_by_cpf solicitado por usuario_id=%s', request.user.id)
    
    cpf = request.data.get('cpf')
    
    if not cpf:
        return Response({'error': 'CPF é obrigatório'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Normalizar CPF
    cpf_limpo = cpf.replace('.', '').replace('-', '')
    
    try:
        usuario = Usuario.objects.get(cpf=cpf_limpo)
        
        # Atualizar campos fornecidos
        alteracoes = []
        
        # Se forneceu NEW_CPF, atualizar o CPF do Usuario também
        if 'new_cpf' in request.data and request.data['new_cpf']:
            new_cpf = request.data['new_cpf'].replace('.', '').replace('-', '')
            usuario.cpf = new_cpf
            # Atualizar username também (se for baseado em CPF)
            if usuario.username and usuario.username.replace('.', '').replace('-', '') == cpf_limpo:
                usuario.username = new_cpf
            alteracoes.append(f"cpf")
        
        if 'email' in request.data:
            usuario.email = request.data['email']
            alteracoes.append(f"email")
        if 'first_name' in request.data:
            usuario.first_name = request.data['first_name']
            alteracoes.append(f"first_name")
        if 'telefone' in request.data:
            usuario.telefone = request.data['telefone']
            alteracoes.append(f"telefone")
        if 'data_nascimento' in request.data:
            data_nascimento = request.data['data_nascimento']
            if data_nascimento:
                is_valid, error_msg, data_normalizada = validate_data_nascimento(data_nascimento)
                if not is_valid:
                    return Response({'error': error_msg}, status=status.HTTP_400_BAD_REQUEST)
                usuario.data_nascimento = data_normalizada
                alteracoes.append(f"data_nascimento")
            else:
                # Se enviou None ou string vazia, limpar o campo
                usuario.data_nascimento = None
                alteracoes.append(f"data_nascimento")
        
        if not alteracoes:
            return Response({'warning': 'Nenhum campo para atualizar'}, status=status.HTTP_200_OK)
        
        usuario.save()
        logger.info('sync_usuario_by_cpf atualizou usuario_id=%s campos=%s', usuario.id, ','.join(alteracoes))
        
        return Response({
            'id': usuario.id,
            'username': usuario.username,
            'email': usuario.email,
            'first_name': usuario.first_name,
            'telefone': usuario.telefone,
            'updated_fields': alteracoes
        }, status=status.HTTP_200_OK)
        
    except Usuario.DoesNotExist:
        return Response(
            {'error': f'Usuario com CPF {cpf_limpo} não encontrado no banco'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        logger.exception('Erro ao sincronizar usuário por CPF')
        return Response({'error': 'Erro interno do servidor'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['PATCH'])
@permission_classes([IsAdminUser])
def sync_usuario_by_cnpj(request):
    """
    Sincroniza dados do Usuario quando Empresa é editada
    PATCH /api/sync/usuario/cnpj/
    Body: {
        "cnpj": "12345678000190",
        "email": "novo@empresa.com",
        "first_name": "Nome Empresa Novo",
        "telefone": "1133334444"
    }
    """
    logger.info('sync_usuario_by_cnpj solicitado por usuario_id=%s', request.user.id)
    
    cnpj = request.data.get('cnpj')
    
    if not cnpj:
        return Response({'error': 'CNPJ é obrigatório'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Normalizar CNPJ
    cnpj_limpo = cnpj.replace('.', '').replace('/', '').replace('-', '')
    
    try:
        usuario = Usuario.objects.get(cnpj=cnpj_limpo)
        
        # Atualizar campos fornecidos
        alteracoes = []
        
        # Se forneceu NEW_CNPJ, atualizar o CNPJ do Usuario também
        if 'new_cnpj' in request.data and request.data['new_cnpj']:
            new_cnpj = request.data['new_cnpj'].replace('.', '').replace('/', '').replace('-', '')
            usuario.cnpj = new_cnpj
            # Atualizar username também (se for baseado em CNPJ)
            if usuario.username and usuario.username.replace('.', '').replace('/', '').replace('-', '') == cnpj_limpo:
                usuario.username = new_cnpj
            alteracoes.append(f"cnpj")
        
        if 'email' in request.data:
            usuario.email = request.data['email']
            alteracoes.append(f"email")
        if 'first_name' in request.data:
            usuario.first_name = request.data['first_name']
            alteracoes.append(f"first_name")
        if 'telefone' in request.data:
            usuario.telefone = request.data['telefone']
            alteracoes.append(f"telefone")
        if 'data_nascimento' in request.data:
            data_nascimento = request.data['data_nascimento']
            if data_nascimento:
                is_valid, error_msg, data_normalizada = validate_data_nascimento(data_nascimento)
                if not is_valid:
                    return Response({'error': error_msg}, status=status.HTTP_400_BAD_REQUEST)
                usuario.data_nascimento = data_normalizada
                alteracoes.append(f"data_nascimento")
            else:
                # Se enviou None ou string vazia, limpar o campo
                usuario.data_nascimento = None
                alteracoes.append(f"data_nascimento")
        
        if not alteracoes:
            return Response({'warning': 'Nenhum campo para atualizar'}, status=status.HTTP_200_OK)
        
        usuario.save()
        logger.info('sync_usuario_by_cnpj atualizou usuario_id=%s campos=%s', usuario.id, ','.join(alteracoes))
        
        return Response({
            'id': usuario.id,
            'username': usuario.username,
            'email': usuario.email,
            'first_name': usuario.first_name,
            'telefone': usuario.telefone,
            'updated_fields': alteracoes
        }, status=status.HTTP_200_OK)
        
    except Usuario.DoesNotExist:
        return Response(
            {'error': f'Usuario com CNPJ {cnpj_limpo} não encontrado no banco'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        logger.exception('Erro ao sincronizar usuário por CNPJ')
        return Response({'error': 'Erro interno do servidor'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['DELETE'])
@permission_classes([IsAdminUser])
def delete_usuario_by_cpf(request):
    """
    Deleta Usuario por CPF (usado internamente quando Person é excluída)
    DELETE /api/delete/usuario/cpf/
    """
    logger.info('delete_usuario_by_cpf solicitado por usuario_id=%s', request.user.id)
    
    cpf = request.query_params.get('cpf') or request.data.get('cpf')
    
    if not cpf:
        return Response({'error': 'CPF é obrigatório'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Normalizar CPF
    cpf_limpo = cpf.replace('.', '').replace('-', '')
    
    try:
        usuario = Usuario.objects.get(cpf=cpf_limpo)

        from report.models import Person, Empresa, Endereco, Propriedade

        enderecos_candidatos = set()

        pessoa = Person.objects.filter(usuario=usuario).first() or Person.objects.filter(cpf=cpf_limpo).first()
        if pessoa and pessoa.endereco_id:
            enderecos_candidatos.add(pessoa.endereco_id)

        empresa = None
        if usuario.cnpj:
            cnpj_limpo = usuario.cnpj.replace('.', '').replace('/', '').replace('-', '')
            empresa = Empresa.objects.filter(usuario=usuario).first() or Empresa.objects.filter(cnpj=cnpj_limpo).first()
            if empresa and empresa.endereco_id:
                enderecos_candidatos.add(empresa.endereco_id)

        if pessoa:
            pessoa.delete()
        if empresa:
            empresa.delete()

        usuario_id = usuario.id
        usuario.delete()

        enderecos_removidos = 0
        for endereco_id in enderecos_candidatos:
            if not Person.objects.filter(endereco_id=endereco_id).exists() \
               and not Empresa.objects.filter(endereco_id=endereco_id).exists() \
               and not Propriedade.objects.filter(endereco_id=endereco_id).exists():
                Endereco.objects.filter(id=endereco_id).delete()
                enderecos_removidos += 1

        logger.info('delete_usuario_by_cpf removeu usuario_id=%s enderecos=%s', usuario_id, enderecos_removidos)
        
        return Response({
            'message': f'Usuario com CPF {cpf_limpo} deletado com sucesso',
            'id': usuario_id,
            'enderecos_removidos': enderecos_removidos,
        }, status=status.HTTP_200_OK)
        
    except Usuario.DoesNotExist:
        return Response(
            {'warning': f'Usuario com CPF {cpf_limpo} não encontrado no banco'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        logger.exception('Erro ao deletar usuário por CPF')
        return Response({'error': 'Erro interno do servidor'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['DELETE'])
@permission_classes([IsAdminUser])
def delete_usuario_by_cnpj(request):
    """
    Deleta Usuario por CNPJ (usado internamente quando Empresa é excluída)
    DELETE /api/delete/usuario/cnpj/
    Params: cnpj=12345678000190
    """
    logger.info('delete_usuario_by_cnpj solicitado por usuario_id=%s', request.user.id)
    
    cnpj = request.query_params.get('cnpj') or request.data.get('cnpj')
    
    if not cnpj:
        return Response({'error': 'CNPJ é obrigatório'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Normalizar CNPJ
    cnpj_limpo = cnpj.replace('.', '').replace('/', '').replace('-', '')
    
    try:
        usuario = Usuario.objects.get(cnpj=cnpj_limpo)

        from report.models import Person, Empresa, Endereco, Propriedade

        enderecos_candidatos = set()

        empresa = Empresa.objects.filter(usuario=usuario).first() or Empresa.objects.filter(cnpj=cnpj_limpo).first()
        if empresa and empresa.endereco_id:
            enderecos_candidatos.add(empresa.endereco_id)

        pessoa = None
        if usuario.cpf:
            cpf_limpo = usuario.cpf.replace('.', '').replace('-', '')
            pessoa = Person.objects.filter(usuario=usuario).first() or Person.objects.filter(cpf=cpf_limpo).first()
            if pessoa and pessoa.endereco_id:
                enderecos_candidatos.add(pessoa.endereco_id)

        if pessoa:
            pessoa.delete()
        if empresa:
            empresa.delete()

        usuario_id = usuario.id
        usuario.delete()

        enderecos_removidos = 0
        for endereco_id in enderecos_candidatos:
            if not Person.objects.filter(endereco_id=endereco_id).exists() \
               and not Empresa.objects.filter(endereco_id=endereco_id).exists() \
               and not Propriedade.objects.filter(endereco_id=endereco_id).exists():
                Endereco.objects.filter(id=endereco_id).delete()
                enderecos_removidos += 1

        logger.info('delete_usuario_by_cnpj removeu usuario_id=%s enderecos=%s', usuario_id, enderecos_removidos)
        
        return Response({
            'message': f'Usuario com CNPJ {cnpj_limpo} deletado com sucesso',
            'id': usuario_id,
            'enderecos_removidos': enderecos_removidos,
        }, status=status.HTTP_200_OK)
        
    except Usuario.DoesNotExist:
        return Response(
            {'warning': f'Usuario com CNPJ {cnpj_limpo} não encontrado no banco'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        logger.exception('Erro ao deletar usuário por CNPJ')
        return Response({'error': 'Erro interno do servidor'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)