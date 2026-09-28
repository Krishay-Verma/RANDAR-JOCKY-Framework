"""Pydantic schemas for the JOCKY API (request bounds enforced here)."""

from typing import Optional

from pydantic import BaseModel, Field

MAX_SCRIPT_CHARS = 20_000


class RunInvestigationRequest(BaseModel):
    script: str = Field(min_length=1, max_length=MAX_SCRIPT_CHARS)


class InvestigationResponse(BaseModel):
    id: int
    investigation_name: str
    endpoint_hostname: str
    started_at: str
    finished_at: str
    findings_count: int
    report_json: dict


class RegisterKeyRequest(BaseModel):
    public_key_pem: str = Field(max_length=8_192)


class UpdateInvestigationRequest(BaseModel):
    investigation_name: Optional[str] = Field(default=None, max_length=200)
    status: Optional[str] = Field(default=None, max_length=20)
    notes: Optional[str] = Field(default=None, max_length=10_000)
