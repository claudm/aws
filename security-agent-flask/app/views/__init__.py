"""Rotas que renderizam template (HTML), separadas das rotas de API (`app/routes/`).

Uma página por módulo; todas registradas no blueprint `bp` criado aqui.
"""
from flask import Blueprint

bp = Blueprint("ui", __name__)

from . import index  # noqa: E402,F401  (importa para registrar as rotas em `bp`)
