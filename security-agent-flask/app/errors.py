class ApiError(Exception):
    """Erro de aplicação convertido em resposta JSON pelo error handler."""

    def __init__(self, status_code: int, message: str, errors=None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.errors = errors
