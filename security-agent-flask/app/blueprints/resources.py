from flask import Blueprint, jsonify, request

from ..aws import list_resources, presign_upload
from ..config import get_settings
from ..errors import ApiError
from ..mock_aws import get_mock_aws_client
from ..providers import get_space
from ..schemas import PresignUploadRequest
from ..validation import dump, dump_list, parse_body

bp = Blueprint("resources", __name__, url_prefix="/api/resources")


@bp.post("/upload-url")
def create_upload_url():
    body = parse_body(PresignUploadRequest)
    space = get_space(body.space_id)
    return jsonify(
        dump(presign_upload(space.region, space.account_id, space.space_id, body.filename, body.content_type))
    )


@bp.get("")
def existing_resources():
    space_id = request.args.get("space_id")
    if not space_id:
        raise ApiError(400, "Parâmetro 'space_id' é obrigatório")
    space = get_space(space_id)
    return jsonify(dump_list(list_resources(space.region, space.space_id)))


@bp.put("/mock-upload")
def mock_upload():
    """Destino do PUT no modo mock (URL devolvida por /upload-url).

    Descarta o conteúdo e só registra o arquivo na memória do MockAwsClient —
    nada é enviado para o S3.
    """
    if get_settings().sa_backend != "memory":
        raise ApiError(404, "Rota disponível apenas no modo mock")
    space_id = request.args.get("space_id")
    key = request.args.get("key")
    if not space_id or not key:
        raise ApiError(400, "Parâmetros 'space_id' e 'key' são obrigatórios")
    obj = get_mock_aws_client().register_upload(space_id, key, request.content_length or 0)
    return jsonify(dump(obj))
