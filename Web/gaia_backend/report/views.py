# report/views.py - VERSÃO CORRIGIDA
from rest_framework import viewsets, status, filters
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from django.http import FileResponse
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator

_MAX_AGREEMENT_LEN = 100
from .models import Propriedade, Laudo, Amostra, Empresa, Person, Endereco
from .serializers import PropriedadeSerializer, LaudoSerializer, AmostraSerializer, EmpresaSerializer, PersonSerializer, EnderecoSerializer
from django.utils import timezone
from .pdf_generator import WebReportGenerator
from authentication.models import Usuario
from authentication.serializers import UsuarioSerializer


def _delete_endereco_if_orphan(endereco_id: int) -> bool:
    """Remove Endereco apenas se não estiver mais referenciado."""
    if not endereco_id:
        return False

    if Person.objects.filter(endereco_id=endereco_id).exists():
        return False
    if Empresa.objects.filter(endereco_id=endereco_id).exists():
        return False
    if Propriedade.objects.filter(endereco_id=endereco_id).exists():
        return False

    Endereco.objects.filter(id=endereco_id).delete()
    return True

class PersonViewSet(viewsets.ModelViewSet):
    """
    ViewSet para Person
    """
    queryset = Person.objects.all()
    serializer_class = PersonSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['cpf', 'email']
    search_fields = ['name', 'cpf', 'email', 'phone_number']
    ordering_fields = ['name', 'nascimento']

    def get_permissions(self):
        """Apenas admins podem deletar pessoas"""
        if self.action == 'destroy':
            return [IsAdminUser()]
        return super().get_permissions()

    def get_queryset(self):
        """Restringe acesso por dono para evitar IDOR."""
        user = self.request.user
        if user.is_staff:
            return Person.objects.all()

        query = Q()
        if hasattr(user, 'cpf') and user.cpf:
            query |= Q(cpf=user.cpf)
        if user.email:
            query |= Q(email=user.email)

        if not query:
            return Person.objects.none()
        return Person.objects.filter(query).distinct()
    
    def destroy(self, request, *args, **kwargs):
        """
        Deleta a pessoa E o usuario associado a dela
        """
        
        pessoa = self.get_object()
        endereco_id = pessoa.endereco_id
        
        # Limpar CPF e procurar Usuario associado
        cpf_originl = pessoa.cpf
        cpf_limpo = pessoa.cpf.replace('.', '').replace('-', '')
        
        # Tentar deletar usuario associado
        usuario_deletado = False
        try:
            usuario = Usuario.objects.filter(cpf=cpf_limpo).first()
            if usuario:
                usuario_id = usuario.id
                usuario.delete()
                usuario_deletado = True
            else:
                pass
        except Exception as e:
            pass
            # NÃO bloqueia a deleção da pessoa
        
        # DELETAR PESSOA - OBRIGATÓRIO
        try:
            pessoa.delete()

            _delete_endereco_if_orphan(endereco_id)
            
            # Retornar resposta de sucesso
            response = Response(status=status.HTTP_204_NO_CONTENT)
            return response
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {'error': f'Falha ao deletar pessoa: {str(e)}'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

class EnderecoViewSet(viewsets.ModelViewSet):
    """
    ViewSet para Endereco
    """
    queryset = Endereco.objects.all()
    serializer_class = EnderecoSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['cep', 'cidade', 'estado']
    search_fields = ['rua', 'cidade', 'estado', 'cep']
    ordering_fields = ['cidade', 'estado']

    def get_queryset(self):
        """Restringe endereços aos recursos vinculados ao usuário logado."""
        user = self.request.user
        if user.is_staff:
            return Endereco.objects.all()

        query = Q(propriedade__usuario=user)

        if hasattr(user, 'cpf') and user.cpf:
            query |= Q(person__cpf=user.cpf)
            query |= Q(propriedade__proprietario_pessoa__cpf=user.cpf)

        if hasattr(user, 'cnpj') and user.cnpj:
            query |= Q(empresa__cnpj=user.cnpj)
            query |= Q(propriedade__proprietario_empresa__cnpj=user.cnpj)

        return Endereco.objects.filter(query).distinct()

class PropriedadeViewSet(viewsets.ModelViewSet):
    queryset = Propriedade.objects.all()
    serializer_class = PropriedadeSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = None  # Desabilita paginação (usuários geralmente têm poucas propriedades)

    def get_permissions(self):
        """Apenas admins podem deletar propriedades"""
        if self.action == 'destroy':
            return [IsAdminUser()]
        return super().get_permissions()

    def get_queryset(self):
        """Filtra propriedades do usuário logado (ou todas se admin)"""
        from django.db.models import Q
        user = self.request.user
        if user.is_staff:  # Admin vê todas as propriedades
            return Propriedade.objects.all()
        
        # Usuário comum vê propriedades que ele tem acesso
        query = Q(usuario=user)  # Propriedades criadas por ele no site
        
        # Propriedades de pessoa física (CPF)
        if hasattr(user, 'cpf') and user.cpf:
            query |= Q(proprietario_pessoa__cpf=user.cpf)
        
        # Propriedades de pessoa jurídica (CNPJ) - verifica se existe empresa com seu CNPJ
        if hasattr(user, 'cnpj') and user.cnpj:
            try:
                empresa = Empresa.objects.get(cnpj=user.cnpj)
                query |= Q(proprietario_empresa=empresa)
            except Empresa.DoesNotExist:
                pass
        
        return Propriedade.objects.filter(query)
    
    def perform_create(self, serializer):
        """Associa automaticamente a propriedade ao usuário logado"""
        serializer.save(usuario=self.request.user)

class LaudoViewSet(viewsets.ModelViewSet):
    """
    ViewSet para laudos - Compatível com software desktop
    """
    queryset = Laudo.objects.all()
    serializer_class = LaudoSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['propriedade', 'ativo']
    search_fields = ['numero_amostra']

    def get_permissions(self):
        """Apenas admins podem deletar laudos"""
        if self.action == 'destroy':
            return [IsAdminUser()]
        return super().get_permissions()

    def get_queryset(self):
        """Filtra laudos das propriedades do usuário (ou todas se admin)"""
        from django.db.models import Q
        from report.models import Empresa
        user = self.request.user
        if user.is_staff:  # Admin vê todos os laudos (publicados ou não)
            return Laudo.objects.all()
        
        # Usuário comum vê APENAS laudos PUBLICADOS de propriedades que ele tem acesso
        query = Q(propriedade__usuario=user)  # Propriedades criadas por ele no site
        
        # Propriedades de pessoa física (CPF)
        if hasattr(user, 'cpf') and user.cpf:
            query |= Q(propriedade__proprietario_pessoa__cpf=user.cpf)
        
        # Propriedades de pessoa jurídica (CNPJ) - verifica se existe empresa com seu CNPJ
        if hasattr(user, 'cnpj') and user.cnpj:
            try:
                empresa = Empresa.objects.get(cnpj=user.cnpj)
                query |= Q(propriedade__proprietario_empresa=empresa)
            except Empresa.DoesNotExist:
                pass
        
        # FILTRO CRÍTICO: Apenas laudos PUBLICADOS para usuários comuns
        return Laudo.objects.filter(query, publicado=True)
    
    @action(detail=False, methods=['get'])
    def por_propriedade(self, request):
        """
        Endpoint específico para software desktop
        URL: /api/laudos/por_propriedade/?propriedade_id=1
        """
        propriedade_id = request.query_params.get('propriedade_id')
        
        if not propriedade_id:
            return Response(
                {'error': 'propriedade_id é obrigatório'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Verifica se propriedade existe
            propriedade = Propriedade.objects.get(
                id=propriedade_id
            )
        except Propriedade.DoesNotExist:
            return Response(
                {'error': 'Propriedade não encontrada'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        laudos = self.get_queryset().filter(propriedade_id=propriedade_id, ativo=True)
        serializer = self.get_serializer(laudos, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def upload_pdf(self, request, pk=None):
        """Upload de arquivo PDF para laudo"""

        if not request.user.is_staff:
            return Response(
                {'error': 'Apenas administradores podem fazer upload'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        laudo = self.get_object()
        
        if 'arquivo_pdf' not in request.FILES:
            return Response(
                {'error': 'Nenhum arquivo enviado'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        arquivo = request.FILES['arquivo_pdf']
        
        # Validação 1: Verificar extensão do arquivo
        if not arquivo.name.lower().endswith('.pdf'):
            return Response(
                {'error': 'Apenas arquivos PDF são permitidos'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validação 2: Verificar MIME e assinatura do arquivo.
        # Alguns clientes HTTP enviam PDF com MIME genérico (ex.: application/octet-stream).
        allowed_mime = {
            'application/pdf',
            'application/x-pdf',
            'application/octet-stream',
        }
        content_type = (arquivo.content_type or '').lower()

        # Assinatura mínima de PDF: começa com "%PDF-"
        try:
            file_signature = arquivo.read(5)
            arquivo.seek(0)
        except Exception:
            file_signature = b''

        is_pdf_signature = file_signature == b'%PDF-'

        if content_type not in allowed_mime and not is_pdf_signature:
            return Response(
                {'error': 'Tipo de arquivo inválido'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Se veio como MIME genérico, exige assinatura PDF válida para segurança.
        if content_type in {'application/octet-stream', ''} and not is_pdf_signature:
            return Response(
                {'error': 'Tipo de arquivo inválido'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validação 3: Verificar tamanho (máximo 10MB)
        max_size = 10 * 1024 * 1024  # 10MB em bytes
        if arquivo.size > max_size:
            return Response(
                {'error': f'Arquivo muito grande. Tamanho máximo: 10MB'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        
        laudo.arquivo_pdf = arquivo
        laudo.save()
        
        
        return Response({
            'success': True,
            'message': 'Arquivo enviado com sucesso',
            'url': laudo.arquivo_pdf.url
        })
    
    @action(detail=True, methods=['post'])
    def publicar(self, request, pk=None):
        """
        Publica um laudo (marca como revisado e disponível para o produtor)
        URL: POST /api/laudos/{id}/publicar/
        Apenas admins podem publicar laudos
        """
        if not request.user.is_staff:
            return Response(
                {'error': 'Apenas administradores podem publicar laudos'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        laudo = self.get_object()
        
        if laudo.publicado:
            return Response(
                {'message': 'Este laudo já foi publicado anteriormente'},
                status=status.HTTP_200_OK
            )
        
        # Marca como publicado
        from django.utils import timezone
        laudo.publicado = True
        laudo.data_publicacao = timezone.now()
        laudo.save()
        
        # TODO: Enviar email para o proprietário notificando que o laudo está disponível
        
        return Response({
            'success': True,
            'message': 'Laudo publicado com sucesso',
            'data_publicacao': laudo.data_publicacao
        })
    
    # Método create adaptado para software desktop
    def create(self, request, *args, **kwargs):
        """
        Criação de laudo compatível com software desktop
        Aceita os mesmos campos que o sistema antigo
        """
        data = request.data.copy()
        
        # Se propriedade_id for passado, converte para propriedade
        if 'propriedade_id' in data:
            data['propriedade'] = data.pop('propriedade_id')
        
        # Adiciona automaticamente o usuário da propriedade
        # Nota: o modelo Propriedade não tem campo "proprietario"; a checagem
        # original dava FieldError. Mantemos apenas a validação de existência.
        if 'propriedade' in data:
            try:
                propriedade = Propriedade.objects.get(id=data['propriedade'])
            except Propriedade.DoesNotExist:
                return Response(
                    {'error': 'Propriedade não encontrada'},
                    status=status.HTTP_404_NOT_FOUND
                )
        
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class AmostraViewSet(viewsets.ModelViewSet):
    """
    ViewSet para amostras - IMPORTANTE: Amostra representa os "laudos" técnicos do sistema antigo
    """
    queryset = Amostra.objects.all()
    serializer_class = AmostraSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['propriedade', 'ativo', 'classificacao']
    search_fields = ['numero_amostra', 'descricao']
    
    def get_permissions(self):
        """Apenas admins podem deletar amostras"""
        if self.action == 'destroy':
            return [IsAdminUser()]
        return super().get_permissions()
    
    def get_queryset(self):
        """Filtra amostras pelas propriedades do usuário"""
        from django.db.models import Q
        from report.models import Empresa
        
        user = self.request.user
        if user.is_staff:  # Admin vê todas as amostras
            return Amostra.objects.all()
        
        # Usuário comum vê amostras de propriedades que ele tem acesso
        query = Q(propriedade__usuario=user)  # Propriedades criadas por ele no site
        
        # Propriedades de pessoa física (CPF)
        if hasattr(user, 'cpf') and user.cpf:
            query |= Q(propriedade__proprietario_pessoa__cpf=user.cpf)
        
        # Propriedades de pessoa jurídica (CNPJ) - verifica se existe empresa com seu CNPJ
        if hasattr(user, 'cnpj') and user.cnpj:
            try:
                empresa = Empresa.objects.get(cnpj=user.cnpj)
                query |= Q(propriedade__proprietario_empresa=empresa)
            except Empresa.DoesNotExist:
                pass
        
        return Amostra.objects.filter(query)
    
    @method_decorator(ratelimit(key='user', rate='10/m', method='ALL', block=True))
    @action(detail=True, methods=['get', 'post'])
    def gerar_laudo(self, request, pk=None):
        """
        Gera e retorna PDF do laudo para uma amostra
        URL: GET /api/amostras/{id}/gerar_laudo/?convenio=texto
        URL: POST /api/amostras/{id}/gerar_laudo/ com {"convenio": "texto"}
        
        Parâmetros:
        - convenio (opcional): Texto do convênio. Default: "Sistema Web GAIA"
        """
        amostra = self.get_object()
        
        # Pegar convênio do query param (GET) ou do body (POST)
        convenio = request.query_params.get('convenio') or request.data.get('convenio', 'Sistema Web GAIA')

        # Validar tamanho do convênio para evitar DoS via string gigante
        if len(str(convenio)) > _MAX_AGREEMENT_LEN:
            return Response(
                {'error': f'Convênio deve ter no máximo {_MAX_AGREEMENT_LEN} caracteres'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Gerar PDF
        pdf_buffer = WebReportGenerator.generate_pdf_for_sample(
            sample_id=amostra.id,
            agreement=convenio
        )
        
        if not pdf_buffer:
            return Response(
                {'error': 'Erro ao gerar PDF do laudo'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        # Retornar PDF como download
        response = FileResponse(
            pdf_buffer,
            content_type='application/pdf',
            as_attachment=True,
            filename=f'Laudo_Amostra_{amostra.numero_amostra}_{amostra.data_coleta}.pdf'
        )
        
        return response
    
    @action(detail=False, methods=['get'])
    def por_propriedade(self, request):
        """
        Endpoint para software desktop - Amostras por propriedade
        URL: /api/amostras/por_propriedade/?propriedade_id=1
        """
        propriedade_id = request.query_params.get('propriedade_id')
        
        if not propriedade_id:
            return Response(
                {'error': 'propriedade_id é obrigatório'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Verifica se propriedade existe
            propriedade = Propriedade.objects.get(
                id=propriedade_id
            )
        except Propriedade.DoesNotExist:
            return Response(
                {'error': 'Propriedade não encontrada'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        amostras = self.get_queryset().filter(propriedade_id=propriedade_id, ativo=True)
        serializer = self.get_serializer(amostras, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'])
    def criar_simples(self, request):
        """
        Criação simplificada para software desktop
        Mapeia campos antigos para novos
        """
        from datetime import date
        
        data = request.data.copy()
        
        # Mapeamento de campos para compatibilidade
        field_mapping = {
            'propriedade_id': 'propriedade',
            'numero_amostra': 'numero_amostra',
            'data_coleta': 'data_coleta',
            'ph': 'ph',
            'smp': 'smp',
            'fosforo': 'fosforo',
            'potassio': 'potassio',
            'materia_organica': 'materia_organica',
            'descricao': 'descricao',
            'argila': 'argila',
            'silte': 'silte',
            'areia': 'areia',
            'classificacao': 'classificacao',
        }
        
        mapped_data = {}
        for old_field, new_field in field_mapping.items():
            if old_field in data:
                mapped_data[new_field] = data[old_field]
        
        # Validar que propriedade foi informada
        if 'propriedade' not in mapped_data:
            return Response(
                {'error': 'propriedade_id é obrigatório'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Gerar número de amostra automático se não informado
        if 'numero_amostra' not in mapped_data:
            try:
                ultima_amostra = Amostra.objects.filter(
                    propriedade=mapped_data['propriedade']
                ).order_by('-numero_amostra').first()
                if ultima_amostra:
                    mapped_data['numero_amostra'] = int(ultima_amostra.numero_amostra) + 1
                else:
                    mapped_data['numero_amostra'] = 1
            except (ValueError, TypeError):
                mapped_data['numero_amostra'] = 1
        
        # Definir data_coleta como hoje se não informada
        if 'data_coleta' not in mapped_data:
            mapped_data['data_coleta'] = str(date.today())
        
        serializer = self.get_serializer(data=mapped_data)
        serializer.is_valid(raise_exception=True)
        
        # Salva a amostra
        serializer.save()
        
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    # ========== ENDPOINT DE INFO PARA SOFTWARE DESKTOP ==========
@api_view(['GET'])
@permission_classes([AllowAny])
def api_info(request):
    """Informações da API para software desktop"""
    return Response({
        'name': 'Lab Solos API',
        'version': '1.0',
        'compatible_with': 'Software Desktop v2.0+',
        'description': 'API para integração do software desktop com sistema web',
        'models_supported': ['Propriedade', 'Laudo', 'Amostra'],
        'endpoints': {
            'auth': {
                'login': 'POST /api/token/',
                'refresh': 'POST /api/token/refresh/',
            },
            'propriedades': {
                'list': 'GET /api/propriedades/',
                'create': 'POST /api/propriedades/',
                'detail': 'GET /api/propriedades/{id}/',
                'buscar': 'GET /api/propriedades/buscar/?q=termo&cpf=...',
                'por_cpf': 'GET /api/propriedades/por_cpf/?cpf=...',
                'amostras': 'GET /api/propriedades/{id}/amostras/',
                'laudos': 'GET /api/propriedades/{id}/laudos/',
            },
            'laudos': {
                'list': 'GET /api/laudos/',
                'create': 'POST /api/laudos/',
                'detail': 'GET /api/laudos/{id}/',
                'por_propriedade': 'GET /api/laudos/por_propriedade/?propriedade_id=1',
                'upload_pdf': 'POST /api/laudos/{id}/upload_pdf/',
            },
            'amostras': {
                'list': 'GET /api/amostras/',
                'create': 'POST /api/amostras/',
                'detail': 'GET /api/amostras/{id}/',
                'por_propriedade': 'GET /api/amostras/por_propriedade/?propriedade_id=1',
                'criar_simples': 'POST /api/amostras/criar_simples/',
            }
        },
        'authentication': 'Bearer token JWT',
        'cors': 'Habilitado para todas as origens'
    })

# ========== ENDPOINT DE SAÚDE ==========
@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """Endpoint de verificação de saúde da API"""
    return Response({
        'status': 'healthy',
        'timestamp': timezone.now().isoformat(),
        'version': '1.0'
    })

# Endpoint para buscar usuário atual
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def current_user(request):
    """Retorna informações do usuário atual"""
    serializer = UsuarioSerializer(request.user)
    return Response(serializer.data)

# Endpoint para empresas (se necessário)
class EmpresaViewSet(viewsets.ModelViewSet):
    queryset = Empresa.objects.all()
    serializer_class = EmpresaSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['cnpj', 'email']
    search_fields = ['name', 'cnpj', 'email', 'telefone']
    ordering_fields = ['name']
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['cnpj', 'email']
    search_fields = ['name', 'cnpj', 'email', 'telefone']
    ordering_fields = ['name']

    def get_permissions(self):
        """Apenas admins podem deletar empresas"""
        if self.action == 'destroy':
            return [IsAdminUser()]
        return super().get_permissions()

    def get_queryset(self):
        """Restringe acesso por dono para evitar IDOR."""
        user = self.request.user
        if user.is_staff:
            return Empresa.objects.all()

        query = Q()
        if hasattr(user, 'cnpj') and user.cnpj:
            query |= Q(cnpj=user.cnpj)
        if user.email:
            query |= Q(email=user.email)

        if not query:
            return Empresa.objects.none()
        return Empresa.objects.filter(query).distinct()
    
    def destroy(self, request, *args, **kwargs):
        """
        Deleta a empresa E o usuario associado a ela
        """
        
        empresa = self.get_object()
        endereco_id = empresa.endereco_id
        
        # Limpar CNPJ e procurar Usuario associado
        cnpj_limpo = empresa.cnpj.replace('.', '').replace('/', '').replace('-', '')
        
        # Tentar deletar usuario associado
        usuario_deletado = False
        try:
            usuario = Usuario.objects.filter(cnpj=cnpj_limpo).first()
            if usuario:
                usuario_id = usuario.id
                usuario.delete()
                usuario_deletado = True
            else:
                pass
        except Exception as e:
            pass
            # NÃO bloqueia a deleção da empresa
        
        # DELETAR EMPRESA - OBRIGATÓRIO
        try:
            empresa.delete()

            _delete_endereco_if_orphan(endereco_id)
            
            # Retornar resposta de sucesso
            response = Response(status=status.HTTP_204_NO_CONTENT)
            return response
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {'error': f'Falha ao deletar empresa: {str(e)}'}, 
                status=status.HTTP_400_BAD_REQUEST
            )