class DomainException(Exception):
    """Exceção base para todo o domínio da aplicação."""
    pass


class JobConfigurationError(DomainException):
    """Lançada quando a configuração do job ou arquivo de entrada é inválida ou inacessível."""
    pass


class SecurityAgentConnectionError(DomainException):
    """Lançada em caso de falhas na comunicação externa com o AWS Security Agent."""
    pass


class PentestExecutionTimeoutError(DomainException):
    """Lançada quando o Job de teste ultrapassa o limite de tempo para conclusão."""
    pass
