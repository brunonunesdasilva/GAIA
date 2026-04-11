"""
Middleware de segurança para adicionar headers HTTP de proteção
"""

import secrets
import re
from urllib.parse import urlsplit

from django.conf import settings


_JWT_PART_PATTERN = re.compile(r'^[A-Za-z0-9_-]+$')


def _is_likely_jwt(token):
    """Validação mínima de formato JWT para evitar headers malformados."""
    if not token:
        return False

    token = token.strip()
    if len(token) > 4096:
        return False

    parts = token.split('.')
    if len(parts) != 3:
        return False

    return all(part and _JWT_PART_PATTERN.match(part) for part in parts)


def _normalize_origin(origin):
    """Extrai esquema+host(+porta) de uma URL/origem para uso no CSP."""
    if not origin:
        return None

    parsed = urlsplit(origin)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"

    return None


def _build_connect_src_values(is_debug=False):
    """Monta connect-src a partir de origens confiáveis de CORS/CSRF."""
    sources = ["'self'"]
    seen = {"'self'"}

    origins = []
    origins.extend(getattr(settings, 'CORS_ALLOWED_ORIGINS', []) or [])
    origins.extend(getattr(settings, 'CSRF_TRUSTED_ORIGINS', []) or [])

    for origin in origins:
        normalized = _normalize_origin(origin)
        if normalized and normalized not in seen:
            sources.append(normalized)
            seen.add(normalized)

    if is_debug:
        debug_sources = [
            'http://localhost:*',
            'http://127.0.0.1:*',
            'ws://localhost:*',
            'ws://127.0.0.1:*',
        ]
        for source in debug_sources:
            if source not in seen:
                sources.append(source)
                seen.add(source)

    return ' '.join(sources)


class JWTCookieToHeaderMiddleware:
    """
    Middleware que lê o access_token do httpOnly cookie
    e o injeta no Authorization header para validação pelo Django
    
    Isso permite que o backend valide tokens via cookies,
    mantendo a segurança de httpOnly (inacessível via JavaScript)
    """
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Se não há Authorization header, tenta ler do cookie
        if 'HTTP_AUTHORIZATION' not in request.META:
            access_token = request.COOKIES.get('access_token')
            
            if _is_likely_jwt(access_token):
                # Injetar no Authorization header para validação
                request.META['HTTP_AUTHORIZATION'] = f"Bearer {access_token.strip()}"
        
        response = self.get_response(request)
        return response


class SecurityHeadersMiddleware:
    """
    Adiciona headers de segurança essenciais a todas as respostas HTTP
    """
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Nonce único por resposta para permitir scripts/estilos inline confiáveis
        nonce = secrets.token_urlsafe(16)
        request.csp_nonce = nonce
        
        # X-Content-Type-Options: Previne MIME type sniffing
        response['X-Content-Type-Options'] = 'nosniff'
        
        # X-Frame-Options: Já configurado pelo Django, mas garantindo
        if 'X-Frame-Options' not in response:
            response['X-Frame-Options'] = 'DENY'
        
        # Referrer-Policy: Controla informações de referer
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Permissions-Policy: Desabilita APIs perigosas
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        # Content-Security-Policy: em dev, modo mais permissivo e report-only.
        # Em produção, aplica política estrita com nonce.
        connect_src = _build_connect_src_values(is_debug=settings.DEBUG)
        if settings.DEBUG:
            csp_directives = [
                "default-src 'self' data: blob: http: https:",
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' blob: http: https:",
                "style-src 'self' 'unsafe-inline' http: https:",
                "img-src 'self' data: blob: http: https:",
                "font-src 'self' data: http: https:",
                f"connect-src {connect_src}",
                "frame-ancestors 'none'",
            ]
            response['Content-Security-Policy-Report-Only'] = '; '.join(csp_directives)
        else:
            csp_directives = [
                "default-src 'self'",
                f"script-src 'self' 'nonce-{nonce}'",
                f"style-src 'self' 'nonce-{nonce}'",
                "img-src 'self' data: https:",
                "font-src 'self' data:",
                f"connect-src {connect_src}",
                "object-src 'none'",
                "base-uri 'self'",
                "frame-ancestors 'none'",
            ]
            response['Content-Security-Policy'] = '; '.join(csp_directives)
        response['X-CSP-Nonce'] = nonce
        
        return response