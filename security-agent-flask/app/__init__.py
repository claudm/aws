import logging

from flask import Flask, jsonify

from .config import get_settings
from .errors import ApiError
from .mock import get_mock, is_mock

logging.basicConfig(level=logging.INFO)


def create_app() -> Flask:
    settings = get_settings()
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = settings.flask_secret_key

    # Front é servido pelo próprio Flask (mesma origem). CORS só se hospedar fora.
    if settings.cors_origin_list:
        from flask_cors import CORS

        CORS(app, resources={r"/api/*": {"origins": settings.cors_origin_list}})

    from .routes import bp as api
    from .views import bp as ui

    app.register_blueprint(ui)   # páginas (render de template)
    app.register_blueprint(api)  # API JSON sob /api

    @app.errorhandler(ApiError)
    def handle_api_error(exc: ApiError):
        payload = {"detail": exc.message}
        if exc.errors:
            payload["errors"] = exc.errors
        return jsonify(payload), exc.status_code

    if is_mock():
        get_mock()  # liga o moto, semeia a AWS falsa e carrega o estado
    return app
