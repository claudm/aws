import os

from flask import Blueprint, current_app, render_template

from ..config import get_settings

bp = Blueprint("ui", __name__)

REGION_OPTIONS = ["sa-east-1", "us-east-1", "us-west-2", "eu-west-1"]


def _regions(current: str) -> list[str]:
    """Opções do select, sempre incluindo a região configurada (AWS_REGION)."""
    if current and current not in REGION_OPTIONS:
        return [current, *REGION_OPTIONS]
    return REGION_OPTIONS


def _asset_version(*parts: str) -> int:
    """Timestamp do arquivo estático, usado como cache-buster (?v=...)."""
    path = os.path.join(current_app.static_folder, *parts)
    try:
        return int(os.path.getmtime(path))
    except OSError:
        return 0


@bp.get("/")
def index():
    settings = get_settings()
    return render_template(
        "index.html",
        default_account=settings.expected_account_id or "",
        default_region=settings.aws_region,
        regions=_regions(settings.aws_region),
        js_version=_asset_version("js", "app.js"),
        css_version=_asset_version("css", "styles.css"),
    )
