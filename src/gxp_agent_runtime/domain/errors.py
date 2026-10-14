"""Domain errors mapped to HTTP status codes and OAuth-style bodies by the API layer."""

from __future__ import annotations


class GxpError(Exception):
    code = "invalid_request"
    status = 400

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class NotFoundError(GxpError):
    code = "not_found"
    status = 404


class ConflictError(GxpError):
    code = "conflict"
    status = 409


class InvalidStateError(GxpError):
    code = "invalid_state"
    status = 409


class ValidationFailedError(GxpError):
    """Input failed schema, ALCOA+ or definition validation."""

    code = "validation_failed"
    status = 422


class UnauthorizedError(GxpError):
    code = "unauthorized"
    status = 401


class ForbiddenError(GxpError):
    code = "forbidden"
    status = 403


class SignatureError(GxpError):
    """An electronic signature could not be applied (re-authentication, SoD, linkage)."""

    code = "signature_rejected"
    status = 403


class DependencyError(GxpError):
    """An upstream dependency (identity fabric, validated system) is unavailable."""

    code = "dependency_unavailable"
    status = 503
