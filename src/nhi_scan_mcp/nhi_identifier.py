"""NHI identification logic for classifying IAM identities."""

import re
from typing import List
from datetime import datetime, timezone

from .models import (
    IAMUser,
    IAMRole,
    IAMIdentity,
    NHIIdentification,
    NHICategory,
    IdentityType,
)


class NHIIdentifier:
    """Identifies Non-Human Identities in AWS IAM."""

    # Patterns that suggest NHI
    NHI_NAME_PATTERNS = [
        r"service",
        r"^svc[_-]",
        r"^app[_-]",
        r"^api[_-]",
        r"^bot[_-]",
        r"^lambda[_-]",
        r"^ec2[_-]",
        r"^automation",
        r"^deploy",
        r"^ci[_-]",
        r"^cd[_-]",
        r"^jenkins",
        r"^github",
        r"^gitlab",
        r"^circleci",
        r"^terraform",
        r"^ansible",
        r"^system",
        r"^backup",
        r"^monitoring",
        r"^robot",
    ]

    # AWS service principals
    AWS_SERVICE_PRINCIPALS = [
        "lambda.amazonaws.com",
        "ec2.amazonaws.com",
        "ecs-tasks.amazonaws.com",
        "eks.amazonaws.com",
        "apigateway.amazonaws.com",
        "states.amazonaws.com",
        "glue.amazonaws.com",
        "codebuild.amazonaws.com",
        "codepipeline.amazonaws.com",
        "cloudformation.amazonaws.com",
    ]

    def identify_user(self, user: IAMUser) -> NHIIdentification:
        """Identify if an IAM user is an NHI.

        Args:
            user: IAM user to analyze

        Returns:
            NHI identification result
        """
        reasons = []
        confidence = 0.0
        is_nhi = False
        category = NHICategory.UNCERTAIN

        # Check name patterns
        name_lower = user.name.lower()
        for pattern in self.NHI_NAME_PATTERNS:
            if re.search(pattern, name_lower):
                reasons.append(f"Name matches NHI pattern: {pattern}")
                confidence += 0.3

        # Check for lack of password usage (never logged in)
        if user.password_last_used is None:
            reasons.append("Password never used (likely programmatic access only)")
            confidence += 0.2

        # Check for access keys (programmatic access)
        if user.access_keys:
            active_keys = [k for k in user.access_keys if k["Status"] == "Active"]
            if active_keys:
                reasons.append(f"Has {len(active_keys)} active access key(s)")
                confidence += 0.2

        # Check for lack of MFA (humans should have MFA)
        if not user.mfa_devices:
            reasons.append("No MFA devices configured")
            confidence += 0.1

        # Check tags
        if "Type" in user.tags:
            tag_value = user.tags["Type"].lower()
            if any(
                keyword in tag_value
                for keyword in ["service", "bot", "automation", "application"]
            ):
                reasons.append(f"Tagged as: {user.tags['Type']}")
                confidence += 0.3

        # Check for "service" or "bot" explicitly in tags
        for key, value in user.tags.items():
            key_lower = key.lower()
            value_lower = value.lower()
            if "service" in key_lower or "service" in value_lower:
                reasons.append(f"Tag indicates service account: {key}={value}")
                confidence += 0.2
            if "bot" in key_lower or "bot" in value_lower:
                reasons.append(f"Tag indicates bot account: {key}={value}")
                confidence += 0.2

        # Normalize confidence
        confidence = min(confidence, 1.0)

        # Determine if NHI based on confidence threshold
        if confidence >= 0.5:
            is_nhi = True
            # Determine specific category
            if "service" in name_lower or "svc" in name_lower:
                category = NHICategory.SERVICE_ACCOUNT
            elif any(
                keyword in name_lower
                for keyword in ["bot", "automation", "deploy", "ci", "cd"]
            ):
                category = NHICategory.MACHINE_USER
            else:
                category = NHICategory.SERVICE_ACCOUNT
        elif confidence < 0.3:
            # Likely human
            category = NHICategory.HUMAN_USER
        else:
            # Uncertain
            category = NHICategory.UNCERTAIN

        return NHIIdentification(
            identity=user,
            is_nhi=is_nhi,
            nhi_category=category,
            confidence=confidence,
            reasons=reasons,
        )

    def identify_role(self, role: IAMRole) -> NHIIdentification:
        """Identify the type of IAM role.

        Args:
            role: IAM role to analyze

        Returns:
            NHI identification result
        """
        reasons = []
        confidence = 1.0  # Roles are inherently non-human
        is_nhi = True
        category = NHICategory.SERVICE_ROLE

        # Check assume role policy to determine role type
        assume_policy = role.assume_role_policy
        principals = self._extract_principals(assume_policy)

        # Check for AWS service principals
        for principal in principals:
            if any(service in principal for service in self.AWS_SERVICE_PRINCIPALS):
                if "lambda.amazonaws.com" in principal:
                    category = NHICategory.LAMBDA_EXECUTION_ROLE
                    reasons.append("Lambda execution role")
                elif "ec2.amazonaws.com" in principal:
                    category = NHICategory.EC2_INSTANCE_PROFILE
                    reasons.append("EC2 instance profile role")
                else:
                    category = NHICategory.SERVICE_ROLE
                    reasons.append(f"AWS service role: {principal}")
                break

        # Check for cross-account access
        for principal in principals:
            if principal.startswith("arn:aws:iam::") and ":root" in principal:
                account_id = principal.split(":")[4]
                category = NHICategory.CROSS_ACCOUNT_ROLE
                reasons.append(f"Cross-account role (trusts account: {account_id})")
                break

        # Check for federated access (SAML, OIDC)
        for principal in principals:
            if "saml-provider" in principal or "oidc-provider" in principal:
                category = NHICategory.FEDERATED_ROLE
                reasons.append("Federated role (SAML/OIDC)")
                break

        # Check name patterns for application roles
        name_lower = role.name.lower()
        if any(keyword in name_lower for keyword in ["app", "application", "service"]):
            if category == NHICategory.SERVICE_ROLE:
                category = NHICategory.APPLICATION_ROLE
                reasons.append("Application role based on naming")

        # Check tags
        if "Type" in role.tags:
            reasons.append(f"Tagged as: {role.tags['Type']}")

        return NHIIdentification(
            identity=role,
            is_nhi=is_nhi,
            nhi_category=category,
            confidence=confidence,
            reasons=reasons,
        )

    def _extract_principals(self, policy_document: dict) -> List[str]:
        """Extract principals from an assume role policy document.

        Args:
            policy_document: AssumeRolePolicyDocument

        Returns:
            List of principal identifiers
        """
        principals = []

        if "Statement" not in policy_document:
            return principals

        for statement in policy_document["Statement"]:
            if "Principal" not in statement:
                continue

            principal = statement["Principal"]

            # Handle different principal formats
            if isinstance(principal, str):
                principals.append(principal)
            elif isinstance(principal, dict):
                for key, value in principal.items():
                    if isinstance(value, str):
                        principals.append(value)
                    elif isinstance(value, list):
                        principals.extend(value)

        return principals

    def identify_all(
        self, users: List[IAMUser], roles: List[IAMRole]
    ) -> List[NHIIdentification]:
        """Identify all IAM identities.

        Args:
            users: List of IAM users
            roles: List of IAM roles

        Returns:
            List of NHI identifications
        """
        identifications = []

        for user in users:
            identifications.append(self.identify_user(user))

        for role in roles:
            identifications.append(self.identify_role(role))

        return identifications

    def summarize_identifications(
        self, identifications: List[NHIIdentification]
    ) -> dict:
        """Create a summary of NHI identifications.

        Args:
            identifications: List of NHI identifications

        Returns:
            Summary dictionary
        """
        total = len(identifications)
        nhi_count = sum(1 for i in identifications if i.is_nhi)
        human_count = sum(
            1 for i in identifications if i.nhi_category == NHICategory.HUMAN_USER
        )
        uncertain_count = sum(
            1 for i in identifications if i.nhi_category == NHICategory.UNCERTAIN
        )

        # Count by category
        category_counts = {}
        for identification in identifications:
            cat = identification.nhi_category
            category_counts[cat] = category_counts.get(cat, 0) + 1

        # Separate users and roles
        user_ids = [i for i in identifications if i.identity.identity_type == "user"]
        role_ids = [i for i in identifications if i.identity.identity_type == "role"]

        nhi_users = [i for i in user_ids if i.is_nhi]
        human_users = [i for i in user_ids if i.nhi_category == NHICategory.HUMAN_USER]
        uncertain_users = [
            i for i in user_ids if i.nhi_category == NHICategory.UNCERTAIN
        ]

        return {
            "total_identities": total,
            "total_nhi": nhi_count,
            "total_human": human_count,
            "total_uncertain": uncertain_count,
            "category_breakdown": {
                str(k): v for k, v in category_counts.items()
            },
            "users": {
                "total": len(user_ids),
                "nhi": len(nhi_users),
                "human": len(human_users),
                "uncertain": len(uncertain_users),
            },
            "roles": {
                "total": len(role_ids),
                "all_nhi": True,  # All roles are NHI by definition
            },
            "high_confidence_nhi": [
                {
                    "name": i.identity.name,
                    "type": str(i.identity.identity_type),
                    "category": str(i.nhi_category),
                    "confidence": i.confidence,
                }
                for i in identifications
                if i.is_nhi and i.confidence >= 0.7
            ],
        }
