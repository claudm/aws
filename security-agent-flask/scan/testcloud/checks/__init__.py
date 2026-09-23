"""Importar este pacote popula o registry de checks.

Utiliza auto-load para importar dinamicamente todos os módulos de checks (.py) 
deste diretório e registrá-los automaticamente, sem precisar editar este arquivo.
"""

import importlib
import pkgutil

__all__ = []

# Varre dinamicamente todos os arquivos .py na pasta atual (checks/)
for _, module_name, _ in pkgutil.iter_modules(__path__):
    if module_name == "lambda":
        continue  # Ignora arquivo problemático antigo (palavra reservada do Python) se ainda existir
        
    # Importa o módulo dinamicamente
    importlib.import_module(f".{module_name}", package=__name__)
    
    # Registra no __all__ para export
    __all__.append(module_name)

# Após carregar todos os check modules manuais, chama o autoload para as regras full-dinâmicas
from ..registry import autoload_dynamic_checks
autoload_dynamic_checks()
