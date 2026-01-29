"""FastMCP server for AWS IAM NHI scanning."""

import json
from datetime import datetime
from typing import Optional
from fastmcp import FastMCP

from .aws_scanner import AWSIAMScanner
from .nhi_identifier import NHIIdentifier
from .permission_analyzer import PermissionAnalyzer
from .models import ScanResult

# Initialize FastMCP server
mcp = FastMCP("AWS IAM NHI Scanner")

# Global scanner instance (will be initialized per request with credentials)
_scanner_cache = {}


def get_scanner(
    aws_access_key_id: Optional[str] = None,
    aws_secret_access_key: Optional[str] = None,
    aws_session_token: Optional[str] = None,
    region: str = "us-east-1",
) -> AWSIAMScanner:
    """Get or create an AWS IAM scanner instance.

    Args:
        aws_access_key_id: AWS access key ID
        aws_secret_access_key: AWS secret access key
        aws_session_token: AWS session token
        region: AWS region

    Returns:
        AWSIAMScanner instance
    """
    # Create a cache key based on credentials
    cache_key = f"{aws_access_key_id}:{region}"

    if cache_key not in _scanner_cache:
        _scanner_cache[cache_key] = AWSIAMScanner(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            region_name=region,
        )

    return _scanner_cache[cache_key]


@mcp.tool()
def scan_iam_identities(
    aws_access_key_id: Optional[str] = None,
    aws_secret_access_key: Optional[str] = None,
    aws_session_token: Optional[str] = None,
    region: str = "us-east-1",
    include_permissions: bool = False,
) -> str:
    """Scan AWS IAM to identify all users and roles, classify NHIs, and optionally analyze permissions.

    This is the main comprehensive scanning tool that:
    1. Lists all IAM users and roles in the account
    2. Identifies which identities are Non-Human Identities (NHIs)
    3. Classifies NHIs by category (service roles, machine users, etc.)
    4. Optionally analyzes permissions for each identity

    Args:
        aws_access_key_id: AWS access key ID (optional, uses default credential chain if not provided)
        aws_secret_access_key: AWS secret access key (required if access key ID is provided)
        aws_session_token: AWS session token (optional, for temporary credentials)
        region: AWS region (default: us-east-1)
        include_permissions: Whether to include detailed permission analysis (default: False)

    Returns:
        JSON string with complete scan results including NHI identifications and optional permission analysis
    """
    try:
        scanner = get_scanner(
            aws_access_key_id, aws_secret_access_key, aws_session_token, region
        )

        # Get caller identity
        caller_identity = scanner.get_caller_identity()

        # Scan IAM users and roles
        users = scanner.list_users()
        roles = scanner.list_roles()

        # Identify NHIs
        identifier = NHIIdentifier()
        identifications = identifier.identify_all(users, roles)

        # Optionally analyze permissions
        permission_analyses = {}
        if include_permissions:
            analyzer = PermissionAnalyzer(scanner)
            for identification in identifications:
                identity = identification.identity
                if identity.identity_type == "user":
                    analysis = analyzer.analyze_user_permissions(identity)
                else:
                    analysis = analyzer.analyze_role_permissions(identity)
                permission_analyses[identity.arn] = analysis

        # Create summary
        summary = identifier.summarize_identifications(identifications)

        # Build result
        result = ScanResult(
            scan_time=datetime.utcnow(),
            account_id=caller_identity["Account"],
            caller_identity=caller_identity,
            total_users=len(users),
            total_roles=len(roles),
            nhi_identifications=identifications,
            permission_analyses=permission_analyses,
            summary=summary,
        )

        return result.model_dump_json(indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def list_nhi_identities(
    aws_access_key_id: Optional[str] = None,
    aws_secret_access_key: Optional[str] = None,
    aws_session_token: Optional[str] = None,
    region: str = "us-east-1",
    min_confidence: float = 0.5,
) -> str:
    """List all Non-Human Identities (NHIs) in the AWS account.

    This tool focuses specifically on identifying and listing NHIs without
    detailed permission analysis.

    Args:
        aws_access_key_id: AWS access key ID (optional)
        aws_secret_access_key: AWS secret access key
        aws_session_token: AWS session token (optional)
        region: AWS region (default: us-east-1)
        min_confidence: Minimum confidence threshold for NHI classification (0.0-1.0, default: 0.5)

    Returns:
        JSON string with list of identified NHIs and their classifications
    """
    try:
        scanner = get_scanner(
            aws_access_key_id, aws_secret_access_key, aws_session_token, region
        )

        # Scan IAM
        users = scanner.list_users()
        roles = scanner.list_roles()

        # Identify NHIs
        identifier = NHIIdentifier()
        identifications = identifier.identify_all(users, roles)

        # Filter by confidence
        nhi_list = [
            {
                "name": i.identity.name,
                "arn": i.identity.arn,
                "type": str(i.identity.identity_type),
                "category": str(i.nhi_category),
                "confidence": i.confidence,
                "reasons": i.reasons,
                "created_date": i.identity.created_date.isoformat()
                if i.identity.created_date
                else None,
            }
            for i in identifications
            if i.is_nhi and i.confidence >= min_confidence
        ]

        result = {
            "total_nhi": len(nhi_list),
            "min_confidence": min_confidence,
            "identities": nhi_list,
            "summary": identifier.summarize_identifications(identifications),
        }

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def analyze_caller_permissions(
    aws_access_key_id: Optional[str] = None,
    aws_secret_access_key: Optional[str] = None,
    aws_session_token: Optional[str] = None,
    region: str = "us-east-1",
) -> str:
    """Analyze the permissions of the current AWS credentials (caller).

    This tool examines the permissions associated with the provided AWS credentials
    to understand what level of access they have.

    Args:
        aws_access_key_id: AWS access key ID (optional)
        aws_secret_access_key: AWS secret access key
        aws_session_token: AWS session token (optional)
        region: AWS region (default: us-east-1)

    Returns:
        JSON string with detailed permission analysis of the caller
    """
    try:
        scanner = get_scanner(
            aws_access_key_id, aws_secret_access_key, aws_session_token, region
        )

        analyzer = PermissionAnalyzer(scanner)
        analysis = analyzer.analyze_caller_permissions()

        caller_identity = scanner.get_caller_identity()

        result = {
            "caller_identity": caller_identity,
            "permission_analysis": analysis.model_dump(),
        }

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def get_identity_details(
    identity_name: str,
    identity_type: str = "user",
    aws_access_key_id: Optional[str] = None,
    aws_secret_access_key: Optional[str] = None,
    aws_session_token: Optional[str] = None,
    region: str = "us-east-1",
) -> str:
    """Get detailed information about a specific IAM identity including NHI classification and permissions.

    Args:
        identity_name: Name of the IAM user or role
        identity_type: Type of identity - "user" or "role" (default: user)
        aws_access_key_id: AWS access key ID (optional)
        aws_secret_access_key: AWS secret access key
        aws_session_token: AWS session token (optional)
        region: AWS region (default: us-east-1)

    Returns:
        JSON string with detailed information about the identity
    """
    try:
        scanner = get_scanner(
            aws_access_key_id, aws_secret_access_key, aws_session_token, region
        )

        # Get the identity
        if identity_type.lower() == "user":
            users = scanner.list_users()
            identity = next((u for u in users if u.name == identity_name), None)
            if not identity:
                return json.dumps({"error": f"User '{identity_name}' not found"})
        else:
            roles = scanner.list_roles()
            identity = next((r for r in roles if r.name == identity_name), None)
            if not identity:
                return json.dumps({"error": f"Role '{identity_name}' not found"})

        # Classify NHI
        identifier = NHIIdentifier()
        if identity_type.lower() == "user":
            nhi_id = identifier.identify_user(identity)
        else:
            nhi_id = identifier.identify_role(identity)

        # Analyze permissions
        analyzer = PermissionAnalyzer(scanner)
        if identity_type.lower() == "user":
            perm_analysis = analyzer.analyze_user_permissions(identity)
        else:
            perm_analysis = analyzer.analyze_role_permissions(identity)

        result = {
            "identity": identity.model_dump(),
            "nhi_classification": {
                "is_nhi": nhi_id.is_nhi,
                "category": str(nhi_id.nhi_category),
                "confidence": nhi_id.confidence,
                "reasons": nhi_id.reasons,
            },
            "permission_analysis": perm_analysis.model_dump(),
        }

        return json.dumps(result, indent=2, default=str)

    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def distinguish_users_vs_nhi(
    aws_access_key_id: Optional[str] = None,
    aws_secret_access_key: Optional[str] = None,
    aws_session_token: Optional[str] = None,
    region: str = "us-east-1",
) -> str:
    """Distinguish between human users and non-human identities with a detailed summary.

    This tool provides a comprehensive breakdown separating human users from
    various types of NHIs, with statistics and recommendations.

    Args:
        aws_access_key_id: AWS access key ID (optional)
        aws_secret_access_key: AWS secret access key
        aws_session_token: AWS session token (optional)
        region: AWS region (default: us-east-1)

    Returns:
        JSON string with detailed breakdown of human vs non-human identities
    """
    try:
        scanner = get_scanner(
            aws_access_key_id, aws_secret_access_key, aws_session_token, region
        )

        # Scan IAM
        users = scanner.list_users()
        roles = scanner.list_roles()

        # Identify NHIs
        identifier = NHIIdentifier()
        identifications = identifier.identify_all(users, roles)

        # Separate human users from NHIs
        human_users = []
        nhi_users = []
        uncertain_users = []
        all_roles = []

        for identification in identifications:
            if identification.identity.identity_type == "user":
                if identification.nhi_category.value == "human_user":
                    human_users.append({
                        "name": identification.identity.name,
                        "arn": identification.identity.arn,
                        "created_date": identification.identity.created_date.isoformat()
                        if identification.identity.created_date
                        else None,
                        "has_mfa": len(identification.identity.mfa_devices) > 0,
                        "password_last_used": identification.identity.password_last_used.isoformat()
                        if identification.identity.password_last_used
                        else None,
                    })
                elif identification.nhi_category.value == "uncertain":
                    uncertain_users.append({
                        "name": identification.identity.name,
                        "arn": identification.identity.arn,
                        "confidence": identification.confidence,
                        "reasons": identification.reasons,
                    })
                else:
                    nhi_users.append({
                        "name": identification.identity.name,
                        "arn": identification.identity.arn,
                        "category": str(identification.nhi_category),
                        "confidence": identification.confidence,
                        "reasons": identification.reasons,
                    })
            else:
                all_roles.append({
                    "name": identification.identity.name,
                    "arn": identification.identity.arn,
                    "category": str(identification.nhi_category),
                })

        # Generate recommendations
        recommendations = []
        if uncertain_users:
            recommendations.append(
                f"Review {len(uncertain_users)} uncertain user(s) - they may need proper tagging or naming conventions"
            )
        if any(not u.get("has_mfa") for u in human_users):
            no_mfa_count = sum(1 for u in human_users if not u.get("has_mfa"))
            recommendations.append(
                f"Enable MFA for {no_mfa_count} human user(s) without MFA"
            )
        if nhi_users:
            recommendations.append(
                f"Consider migrating {len(nhi_users)} NHI user(s) to IAM roles for better security"
            )

        result = {
            "scan_time": datetime.utcnow().isoformat(),
            "summary": {
                "total_users": len(users),
                "human_users": len(human_users),
                "nhi_users": len(nhi_users),
                "uncertain_users": len(uncertain_users),
                "total_roles": len(roles),
            },
            "human_users": human_users,
            "nhi_users": nhi_users,
            "uncertain_users": uncertain_users,
            "roles_summary": {
                "total": len(all_roles),
                "by_category": {},
            },
            "recommendations": recommendations,
        }

        # Count roles by category
        for role in all_roles:
            cat = role["category"]
            result["roles_summary"]["by_category"][cat] = (
                result["roles_summary"]["by_category"].get(cat, 0) + 1
            )

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


if __name__ == "__main__":
    # Run the MCP server
    mcp.run()
