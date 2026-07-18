"""Safe protocol errors that never carry document or query values."""


class AdapterError(Exception):
    def __init__(
        self, code: str, field: str = "", operation_id: str | None = None
    ) -> None:
        super().__init__(code)
        self.code = code
        self.field = field
        self.operation_id = operation_id


class InvalidRequest(AdapterError):
    def __init__(
        self, field: str = "request", operation_id: str | None = None
    ) -> None:
        super().__init__("invalid_request", field, operation_id)


class Conflict(AdapterError):
    def __init__(self, field: str = "idempotency_key") -> None:
        super().__init__("idempotency_conflict", field)


class DependencyUnavailable(AdapterError):
    def __init__(self, field: str = "dependency") -> None:
        super().__init__("dependency_unavailable", field)


class PersistenceMismatch(AdapterError):
    def __init__(self) -> None:
        super().__init__("persistence_mismatch", "revision_id")


class InvalidContent(AdapterError):
    def __init__(self, field: str = "content") -> None:
        super().__init__("invalid_content", field)
