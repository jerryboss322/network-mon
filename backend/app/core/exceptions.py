"""Domain-specific exception hierarchy for NetPulse."""

from __future__ import annotations

from typing import Any


class NetPulseError(Exception):
    """Base error for all platform domain exceptions."""

    status_code: int = 500
    error_code: str = "INTERNAL_ERROR"

    def __init__(
        self,
        message: str,
        *,
        error_code: str | None = None,
        status_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if error_code is not None:
            self.error_code = error_code
        if status_code is not None:
            self.status_code = status_code
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "error": {
                "code": self.error_code,
                "message": self.message,
                "details": self.details,
            }
        }


class ValidationError(NetPulseError):
    status_code = 422
    error_code = "VALIDATION_ERROR"


class NotFoundError(NetPulseError):
    status_code = 404
    error_code = "NOT_FOUND"


class ConflictError(NetPulseError):
    status_code = 409
    error_code = "CONFLICT"


class AuthenticationError(NetPulseError):
    status_code = 401
    error_code = "AUTHENTICATION_FAILED"


class AuthorizationError(NetPulseError):
    status_code = 403
    error_code = "FORBIDDEN"


class RateLimitError(NetPulseError):
    status_code = 429
    error_code = "RATE_LIMIT_EXCEEDED"


class CollectorError(NetPulseError):
    status_code = 502
    error_code = "COLLECTOR_ERROR"


class ProtocolTimeoutError(CollectorError):
    status_code = 504
    error_code = "PROTOCOL_TIMEOUT"


class SNMPProtocolError(CollectorError):
    error_code = "SNMP_ERROR"


class TopologyCycleError(ValidationError):
    error_code = "TOPOLOGY_CYCLE"


class QuerySyntaxError(ValidationError):
    error_code = "QUERY_SYNTAX_ERROR"


class CompliancePolicyError(ValidationError):
    error_code = "COMPLIANCE_POLICY_ERROR"


class PlaybookExecutionError(NetPulseError):
    status_code = 500
    error_code = "PLAYBOOK_EXECUTION_ERROR"


class VaultDecryptionError(NetPulseError):
    status_code = 500
    error_code = "VAULT_DECRYPTION_ERROR"
