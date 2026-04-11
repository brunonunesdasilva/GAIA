# Novo Database.py para software desktop (API Django)
from typing import List, Dict
import importlib
import os
from backend.classes.Address import Address
from backend.classes.Property import Property

#Compatibilidade total com o código existente, delegando para o backend escolhido (API ou SQLite) sem alterar as assinaturas dos métodos. O wrapper é transparente para o restante do código, permitindo que ele funcione sem modificações, independentemente do backend utilizado.

class Database:
    """Wrapper para manter compatibilidade total com código existente"""
    
    def __init__(self, use_api: bool = True, api_url: str | None = None):
        self.use_api = use_api
        self.db = None

        resolved_api_url = api_url or os.getenv("GAIA_API_URL", "http://localhost:8000")

        if use_api:
            from backend.classes.DatabaseHTTPWrapper import DatabaseHTTPWrapper
            self.db = DatabaseHTTPWrapper(api_url=resolved_api_url)
            print("[API] Modo API Django ativado")

            # Fallback opcional (DESATIVADO): se a API cair, trocar para SQLite local.
            # Para testar depois, descomente este bloco.
            # Requisito: existir backend/classes/DatabaseSQLite.py
            # if not self.db.test_connection():
            #     print("[API] Servidor indisponível. Alternando para SQLite local...")
            #     self._create_sqlite_backend()
        else:
            self._create_sqlite_backend()

    def _create_sqlite_backend(self) -> None:
        """Inicializa backend SQLite local (modo contingência)."""
        try:
            module = importlib.import_module("backend.classes.DatabaseSQLite")
            DatabaseSQLite = getattr(module, "Database")
            self.db = DatabaseSQLite()
            print("[SQLite] Modo SQLite local ativado")
        except ImportError:
            raise ImportError("Nao foi possivel carregar SQLite")
    
    # ========== DELEGACAO DE METODOS ==========
    
    def login(self, cpf: str, password: str) -> bool:
        """Login compativel"""
        if hasattr(self.db, 'login'):
            return self.db.login(cpf, password)
        return False
    
    def insert_property(self, property: Property, requester_id: int, address: Address) -> None:
        """Insere propriedade - Mantem assinatura original"""
        if hasattr(self.db, 'insert_property'):
            self.db.insert_property(property, requester_id, address)
            # O metodo original nao retorna nada, apenas commit
            return
        raise NotImplementedError("Metodo nao implementado")
    
    def get_properties(self, **kwargs) -> list:
        """Busca propriedades - Mantem formato original"""
        if hasattr(self.db, 'get_properties'):
            result = self.db.get_properties(**kwargs)
            # Converter para sqlite3.Row se necess?rio
            return self._convert_to_sqlite_format(result)
        return []
    
    def _convert_to_sqlite_format(self, data: List[Dict]) -> list:
        """Converte dict para formato similar a sqlite3.Row"""
        # Se ja sao objetos com __getitem__, retorna como esta
        if data and hasattr(data[0], '__getitem__'):
            return data

        # Esta eh uma simplificacaoo. Pode precisar de mais ajustes.
        class MockRow:
            def __init__(self, data):
                self._data = data

            def __getitem__(self, key):
                return self._data.get(key)

            def keys(self):
                return self._data.keys()

        return [MockRow(item) for item in data]
    # ========== DELEGAR TODOS OS OUTROS METODOS ==========
    
    def __getattr__(self, name):
        """Delega métodos não implementados para o backend atual"""
        return getattr(self.db, name)


# ========== FÁBRICA PARA ESCOLHA AUTOMÁTICA ==========
def create_database(force_api: bool = False) -> Database:
        """Usa sempre o wrapper compativel"""
        return Database(use_api=True) 