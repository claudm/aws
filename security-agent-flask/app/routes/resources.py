"""Artefatos do pentest: presigned upload e listagem no S3."""
from flask import jsonify, request

from ..aws import list_resources
from ..errors import ApiError
from ..mock import is_mock
from ..providers import get_space, presign_upload
from ..schemas import PresignUploadRequest
from ..validation import dump, dump_list, parse_body
from . import _region, bp


@bp.post("/resources/upload-url")
def create_upload_url():
    body = parse_body(PresignUploadRequest)
    space = get_space(body.space_id)
    return jsonify(
        dump(presign_upload(space.region, space.account_id, space.space_id, body.filename, body.content_type))
    )


@bp.get("/resources")
def existing_resources():
    space_id = request.args.get("space_id")
    if not space_id:
        raise ApiError(400, "Parâmetro 'space_id' é obrigatório")
    space = get_space(space_id)
    return jsonify(dump_list(list_resources(space.region, space.space_id)))


@bp.put("/resources/mock-upload")
def mock_upload():
    """Destino do PUT no modo mock (URL devolvida por /upload-url).

    Descarta o conteúdo e só registra o arquivo na memória do MockState —
    nada é enviado para o S3.
    """
    if not is_mock():
        raise ApiError(404, "Rota disponível apenas no modo mock")
    space_id = request.args.get("space_id")
    key = request.args.get("key")
    if not space_id or not key:
        raise ApiError(400, "Parâmetros 'space_id' e 'key' são obrigatórios")
    from ..mock_aws import store_artifact

    obj = store_artifact(_region(), key, request.content_length or 0)
    return jsonify(dump(obj))
