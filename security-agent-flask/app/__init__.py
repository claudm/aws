import logging

from flask import Flask, jsonify

from .config import get_settings
from .errors import ApiError
from .store import get_store

logging.basicConfig(level=logging.INFO)


def create_app() -> Flask:
    settings = get_settings()
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = settings.flask_secret_key

    # Front é servido pelo próprio Flask (mesma origem). CORS só se hospedar fora.
    if settings.cors_origin_list:
        from flask_cors import CORS

        CORS(app, resources={r"/api/*": {"origins": settings.cors_origin_list}})

    from .blueprints import context, network, pentests, resources, targets, ui

    for module in (ui, context, network, targets, pentests, resources):
        app.register_blueprint(module.bp)

    @app.errorhandler(ApiError)
    def handle_api_error(exc: ApiError):
        payload = {"detail": exc.message}
        if exc.errors:
            payload["errors"] = exc.errors
        return jsonify(payload), exc.status_code

    @app.get("/api/health")
    def health():
        return jsonify(
            {
                "status": "ok",
                "sa_backend": settings.sa_backend,
                "store_backend": settings.store_backend,
                "region": settings.aws_region,
            }
        )

    get_store()  # inicializa o store (mock em memória ou DynamoDB)
    return app
