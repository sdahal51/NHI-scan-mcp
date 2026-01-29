"""Data models for NHI scanning and analysis."""

from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class IdentityType(str, Enum):
    USER = "user"
    ROLE = "role"
    SERVICE_ACCOUNT = "service_account"
    UNKNOWN = "unknown"


class NHICategory(str, Enum):
    SERVICE_ROLE = "service_role"
    MACHINE_USER = "machine_user"
    SERVICE_ACCOUNT = "service_account"
    APPLICATION_ROLE = "application_role"
    LAMBDA_EXECUTION_ROLE = "lambda_execution_role"
    EC2_INSTANCE_PROFILE = "ec2_instance_profile"
    CROSS_ACCOUNT_ROLE = "cross_account_role"
    FEDERATED_ROLE = "federated_role"
    HUMAN_USER = "human_user"
    UNCERTAIN = "uncertain"


class IAMIdentity(BaseModel):
    arn: str
    name: str
    identity_type: IdentityType
    created_date: Optional[datetime] = None
    tags: Dict[str, str] = Field(default_factory=dict)

    class Config:
        use_enum_values = True


class IAMUser(IAMIdentity):
    user_id: str
    path: str
    password_last_used: Optional[datetime] = None
    access_keys: List[Dict[str, Any]] = Field(default_factory=list)
    mfa_devices: List[str] = Field(default_factory=list)
    identity_type: IdentityType = IdentityType.USER


class IAMRole(IAMIdentity):
    role_id: str
    path: str
    assume_role_policy: Dict[str, Any]
    max_session_duration: int
    last_used: Optional[datetime] = None
    identity_type: IdentityType = IdentityType.ROLE


class NHIIdentification(BaseModel):
    identity: IAMIdentity
    is_nhi: bool
    nhi_category: NHICategory
    confidence: float = Field(ge=0.0, le=1.0)
    reasons: List[str] = Field(default_factory=list)

    class Config:
        use_enum_values = True


class PermissionLevel(str, Enum):
    ADMIN = "admin"
    POWER_USER = "power_user"
    READ_WRITE = "read_write"
    READ_ONLY = "read_only"
    LIMITED = "limited"
    NONE = "none"


class PermissionAnalysis(BaseModel):
    identity_arn: str
    permission_level: PermissionLevel
    attached_policies: List[str] = Field(default_factory=list)
    inline_policies: List[str] = Field(default_factory=list)
    group_memberships: List[str] = Field(default_factory=list)
    admin_access: bool = False
    dangerous_permissions: List[str] = Field(default_factory=list)
    resource_access: Dict[str, List[str]] = Field(default_factory=dict)

    class Config:
        use_enum_values = True


class ScanResult(BaseModel):
    scan_time: datetime
    account_id: str
    caller_identity: Dict[str, Any]
    total_users: int
    total_roles: int
    nhi_identifications: List[NHIIdentification]
    permission_analyses: Dict[str, PermissionAnalysis] = Field(default_factory=dict)
    summary: Optional[Dict[str, Any]] = None
