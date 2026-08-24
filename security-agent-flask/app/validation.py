from pydantic import BaseModel, ValidationError

from .errors import ApiError


def parse_body(model: type[BaseModel]):
    """Valida request.json contra um schema Pydantic ou levanta 400."""
    from flask import request

    data = request.get_json(silent=True) or {}
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise ApiError(400, "Dados inválidos", errors=exc.errors(include_url=False))


def dump(model) -> dict:
    return model.model_dump(mode="json")


def dump_list(models) -> list[dict]:
    return [m.model_dump(mode="json") for m in models]
