"""HTTP response envelopes (request bodies are the application commands)."""

from __future__ import annotations

from pydantic import BaseModel

from gxp_agent_runtime.application.commands import ActionCatalogEntry, RequestView
from gxp_agent_runtime.domain.models import (
    ActionDefinition,
    ElectronicSignature,
    ValidatedSystem,
)


class SystemList(BaseModel):
    items: list[ValidatedSystem]


class DefinitionList(BaseModel):
    items: list[ActionDefinition]


class ActionCatalog(BaseModel):
    items: list[ActionCatalogEntry]


class RequestList(BaseModel):
    items: list[RequestView]
    limit: int
    offset: int


class SignatureList(BaseModel):
    items: list[ElectronicSignature]


class OAuthError(BaseModel):
    error: str
    error_description: str
