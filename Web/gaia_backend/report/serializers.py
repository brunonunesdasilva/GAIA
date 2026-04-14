from rest_framework import serializers
from .models import Propriedade, Laudo, Amostra, Empresa, Person, Endereco
from authentication.views import validate_data_nascimento
from django.conf import settings

class AmostraSerializer(serializers.ModelSerializer):
    
    propriedade_name = serializers.CharField(source='propriedade.name', read_only=True)
    propriedade_id = serializers.IntegerField(write_only=True, required=False)
    
    class Meta:
        model = Amostra
        fields = '__all__'
        read_only_fields = ['usuario', 'data_cadastro']
    
    def create(self, validated_data):
        # O campo usuario sera preenchido automaticamente pelo save() do modelo
        # Nao atribuimos o request.user aqui pois ele eh um Usuario, nao uma Person
        return super().create(validated_data)
    
    def to_internal_value(self, data):
        # Mapear propriedade_id para propriedade se fornecido
        if 'propriedade_id' in data and 'propriedade' not in data:
            data['propriedade'] = data.pop('propriedade_id')
        return super().to_internal_value(data)


class LaudoSerializer(serializers.ModelSerializer):
    solicitante_nome = serializers.SerializerMethodField()
    propriedade_nome = serializers.CharField(source='propriedade.name', read_only=True)
    arquivo_url = serializers.SerializerMethodField()
    
    class Meta:
        model = Laudo
        fields = '__all__'
    
    def get_solicitante_nome(self, obj):
        """Retorna o nome do solicitante (proprietário da propriedade)"""
        if obj.propriedade:
            proprietario = obj.propriedade.proprietario
            if proprietario:
                return proprietario.name
        return 'Não informado'
    
    def get_arquivo_url(self, obj):
        """Gera a URL completa para baixar o PDF"""
        if obj.arquivo_pdf:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.arquivo_pdf.url)
            backend_url = getattr(settings, 'BACKEND_PUBLIC_URL', '')
            if backend_url:
                return f"{backend_url.rstrip('/')}{obj.arquivo_pdf.url}"
        return None
    
class EmpresaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Empresa
        fields = '__all__'
    
    def validate_cnpj(self, value):
        """Valida CNPJ único"""
        # Remover formatação
        cnpj_limpo = ''.join(filter(str.isdigit, str(value)))
        
        instance = self.instance
        if instance:
            # Atualização - verificar se mudou
            if Empresa.objects.filter(cnpj=cnpj_limpo).exclude(id=instance.id).exists():
                raise serializers.ValidationError(
                    f'CNPJ {value} já está cadastrado para outra empresa.'
                )
        else:
            # Criação - verificar se já existe
            if Empresa.objects.filter(cnpj=cnpj_limpo).exists():
                raise serializers.ValidationError(
                    f'CNPJ {value} já está cadastrado.'
                )
        
        return cnpj_limpo
    
    def validate_email(self, value):
        """Valida email único (verifica em Empresa E Person)"""
        if not value:  # Email é opcional
            return value
        
        instance = self.instance
        if instance:
            # Atualização - verificar se mudou
            if Empresa.objects.filter(email=value).exclude(id=instance.id).exists():
                raise serializers.ValidationError(
                    f'Email {value} já está cadastrado para outra empresa.'
                )
        else:
            # Criação - verificar se já existe em Empresa
            if Empresa.objects.filter(email=value).exists():
                raise serializers.ValidationError(
                    f'Email {value} já está cadastrado para outra empresa.'
                )
        
        # Verificar se email existe em Person (cross-table validation)
        if Person.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                f'Email {value} já está cadastrado para uma pessoa.'
            )
        
        return value
    
    def update(self, instance, validated_data):
        """
        Método explícito para UPDATE - FORÇA a persistência dos dados
        """
        print(f"\n EmpresaSerializer.update() CHAMADO", flush=True)
        print(f"   Instance ID: {instance.id}", flush=True)
        print(f"   Validated data: {validated_data}", flush=True)
        
        # Atualizar cada campo
        for attr, value in validated_data.items():
            print(f"   Atualizando {attr}: {getattr(instance, attr, 'N/A')} → {value}", flush=True)
            setattr(instance, attr, value)
        
        # SALVAR EXPLICITAMENTE
        print(f"    Salvando no banco de dados...", flush=True)
        instance.save()
        
        # Verificar que foi salvo
        instance.refresh_from_db()
        print(f"    Salvo! Verificação pós-save:", flush=True)
        for attr in validated_data.keys():
            print(f"      {attr}: {getattr(instance, attr)}", flush=True)
        
        return instance

class PersonSerializer(serializers.ModelSerializer):
    class Meta:
        model = Person
        fields = '__all__'
    
    def validate_cpf(self, value):
        """Valida CPF único no modelo Person (report)"""
        # Remover formatação
        cpf_limpo = ''.join(filter(str.isdigit, str(value)))
        
        # Verificar se já existe (exceto se for atualização)
        instance = self.instance
        if instance:
            # Atualização - verificar se mudou
            if Person.objects.filter(cpf=cpf_limpo).exclude(id=instance.id).exists():
                raise serializers.ValidationError(
                    f'CPF {value} já está cadastrado para outra pessoa.'
                )
        else:
            # Criação - verificar se já existe
            if Person.objects.filter(cpf=cpf_limpo).exists():
                raise serializers.ValidationError(
                    f'CPF {value} já está cadastrado.'
                )
        
        return cpf_limpo
    
    def validate_email(self, value):
        """Valida email único (verifica em Person E Empresa)"""
        if not value:  # Email é opcional
            return value
        
        instance = self.instance
        if instance:
            # Atualização - verificar se mudou
            if Person.objects.filter(email=value).exclude(id=instance.id).exists():
                raise serializers.ValidationError(
                    f'Email {value} já está cadastrado para outra pessoa.'
                )
        else:
            # Criação - verificar se já existe em Person
            if Person.objects.filter(email=value).exists():
                raise serializers.ValidationError(
                    f'Email {value} já está cadastrado para outra pessoa.'
                )
        
        # Verificar se email existe em Empresa (cross-table validation)
        if Empresa.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                f'Email {value} já está cadastrado para uma empresa.'
            )
        
        return value
    
    def validate_nascimento(self, value):
        """Valida data de nascimento - não pode ser futura e idade deve estar entre 18 e 120 anos"""
        if not value:  # Campo opcional
            return value
        
        # Usar a função compartilhada de validação
        is_valid, error_msg, data_normalizada = validate_data_nascimento(value)
        
        if not is_valid:
            raise serializers.ValidationError(error_msg)
        
        return data_normalizada
    
    def update(self, instance, validated_data):
        """
        Método explícito para UPDATE - FORÇA a persistência dos dados
        
        O genérico do ModelSerializer às vezes não atualiza corretamente
        Este método garante que TODOS os campos são atualizados
        """
        print(f"\n PersonSerializer.update() CHAMADO", flush=True)
        print(f"   Instance ID: {instance.id}", flush=True)
        print(f"   Validated data: {validated_data}", flush=True)
        
        # Atualizar cada campo
        for attr, value in validated_data.items():
            print(f"   Atualizando {attr}: {getattr(instance, attr, 'N/A')} → {value}", flush=True)
            setattr(instance, attr, value)
        
        # SALVAR EXPLICITAMENTE
        print(f"    Salvando no banco de dados...", flush=True)
        instance.save()
        
        # Verificar que foi salvo
        instance.refresh_from_db()
        print(f"    Salvo! Verificação pós-save:", flush=True)
        for attr in validated_data.keys():
            print(f"      {attr}: {getattr(instance, attr)}", flush=True)
        
        return instance

class EnderecoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Endereco
        fields = '__all__'

class PropriedadeSerializer(serializers.ModelSerializer):
    proprietario_id = serializers.IntegerField(write_only=True, required=True, 
                                               error_messages={
                                                   'required': 'Propriedade DEVE ter um proprietário (pessoa ou empresa)!',
                                                   'null': 'Proprietário não pode ser nulo!'
                                               })
    endereco_detalhes = EnderecoSerializer(source='endereco', read_only=True)
    

    class Meta:
        model = Propriedade
        fields = '__all__'

    def create(self, validated_data):
        print(f"DEBUG PropriedadeSerializer.create: {validated_data}")
        
        proprietario_id = validated_data.pop('proprietario_id', None)
        
        # VALIDAÇÃO CRÍTICA: proprietario_id é OBRIGATÓRIO
        if not proprietario_id:
            raise serializers.ValidationError({
                'proprietario_id': 'ERRO CRÍTICO: Propriedade não pode ser criada sem proprietário!'
            })

        # tenta pessoa
        pessoa = Person.objects.filter(id=proprietario_id).first()
        if pessoa:
            print(f"    Proprietário encontrado: Person ID {pessoa.id} - {pessoa.name}")
            validated_data['proprietario_pessoa'] = pessoa
            return super().create(validated_data)

        # tenta empresa
        empresa = Empresa.objects.filter(id=proprietario_id).first()
        if empresa:
            print(f"    Proprietário encontrado: Empresa ID {empresa.id} - {empresa.name}")
            validated_data['proprietario_empresa'] = empresa
            return super().create(validated_data)

        # NENHUM proprietário encontrado - ERRO CRÍTICO
        raise serializers.ValidationError({
            'proprietario_id': f'Proprietário com ID {proprietario_id} não encontrado. '
                              f'Verifique se pessoa/empresa existe no sistema.'
        })
