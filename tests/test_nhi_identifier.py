"""Tests for NHI identifier."""

import pytest
from datetime import datetime

from src.nhi_scan_mcp.models import IAMUser, IAMRole, NHICategory
from src.nhi_scan_mcp.nhi_identifier import NHIIdentifier


def test_identify_service_user():
    """Test identification of a service user."""
    user = IAMUser(
        arn="arn:aws:iam::123456789012:user/svc-api-backend",
        name="svc-api-backend",
        user_id="AIDAI123456789012345",
        path="/",
        created_date=datetime.now(),
        password_last_used=None,
        access_keys=[{"AccessKeyId": "AKIAI123456789012345", "Status": "Active"}],
        mfa_devices=[],
    )

    identifier = NHIIdentifier()
    result = identifier.identify_user(user)

    assert result.is_nhi is True
    assert result.confidence > 0.5
    assert result.nhi_category in [
        NHICategory.SERVICE_ACCOUNT,
        NHICategory.MACHINE_USER,
    ]


def test_identify_human_user():
    """Test identification of a human user."""
    user = IAMUser(
        arn="arn:aws:iam::123456789012:user/john.doe",
        name="john.doe",
        user_id="AIDAI123456789012345",
        path="/",
        created_date=datetime.now(),
        password_last_used=datetime.now(),
        access_keys=[],
        mfa_devices=["arn:aws:iam::123456789012:mfa/john.doe"],
    )

    identifier = NHIIdentifier()
    result = identifier.identify_user(user)

    assert result.is_nhi is False
    assert result.nhi_category == NHICategory.HUMAN_USER


def test_identify_lambda_role():
    """Test identification of a Lambda execution role."""
    role = IAMRole(
        arn="arn:aws:iam::123456789012:role/lambda-execution-role",
        name="lambda-execution-role",
        role_id="AROAI123456789012345",
        path="/",
        created_date=datetime.now(),
        assume_role_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
        max_session_duration=3600,
    )

    identifier = NHIIdentifier()
    result = identifier.identify_role(role)

    assert result.is_nhi is True
    assert result.nhi_category == NHICategory.LAMBDA_EXECUTION_ROLE


def test_identify_cross_account_role():
    """Test identification of a cross-account role."""
    role = IAMRole(
        arn="arn:aws:iam::123456789012:role/cross-account-access",
        name="cross-account-access",
        role_id="AROAI123456789012345",
        path="/",
        created_date=datetime.now(),
        assume_role_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
        max_session_duration=3600,
    )

    identifier = NHIIdentifier()
    result = identifier.identify_role(role)

    assert result.is_nhi is True
    assert result.nhi_category == NHICategory.CROSS_ACCOUNT_ROLE


def test_summarize_identifications():
    """Test summarization of identifications."""
    users = [
        IAMUser(
            arn=f"arn:aws:iam::123456789012:user/user{i}",
            name=f"user{i}",
            user_id=f"AIDAI12345678901234{i}",
            path="/",
            created_date=datetime.now(),
        )
        for i in range(3)
    ]

    roles = [
        IAMRole(
            arn=f"arn:aws:iam::123456789012:role/role{i}",
            name=f"role{i}",
            role_id=f"AROAI12345678901234{i}",
            path="/",
            created_date=datetime.now(),
            assume_role_policy={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            },
            max_session_duration=3600,
        )
        for i in range(2)
    ]

    identifier = NHIIdentifier()
    identifications = identifier.identify_all(users, roles)
    summary = identifier.summarize_identifications(identifications)

    assert summary["total_identities"] == 5
    assert summary["users"]["total"] == 3
    assert summary["roles"]["total"] == 2
    assert summary["roles"]["all_nhi"] is True
