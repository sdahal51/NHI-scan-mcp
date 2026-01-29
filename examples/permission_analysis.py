"""
Example demonstrating permission analysis for IAM identities.

This example shows:
1. Analyzing permissions for specific users/roles
2. Understanding permission levels
3. Identifying dangerous permissions
"""

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.nhi_scan_mcp.aws_scanner import AWSIAMScanner
from src.nhi_scan_mcp.permission_analyzer import PermissionAnalyzer


def main():
    """Analyze IAM permissions."""
    print("=== AWS IAM Permission Analyzer ===\n")

    # Initialize scanner
    scanner = AWSIAMScanner()

    # Get caller identity
    caller = scanner.get_caller_identity()
    print(f"Analyzing IAM for account: {caller['Account']}\n")

    # Analyze caller's own permissions
    print("1. Analyzing your (caller's) permissions...")
    analyzer = PermissionAnalyzer(scanner)
    caller_analysis = analyzer.analyze_caller_permissions()

    print(f"   Your ARN: {caller_analysis.identity_arn}")
    print(f"   Permission Level: {caller_analysis.permission_level}")
    print(f"   Admin Access: {caller_analysis.admin_access}")
    print(f"   Attached Policies: {len(caller_analysis.attached_policies)}")
    print(f"   Inline Policies: {len(caller_analysis.inline_policies)}")

    if caller_analysis.dangerous_permissions:
        print(f"\n   ⚠️  Dangerous Permissions Detected:")
        for perm in caller_analysis.dangerous_permissions[:5]:  # Show first 5
            print(f"      - {perm}")
        if len(caller_analysis.dangerous_permissions) > 5:
            print(f"      ... and {len(caller_analysis.dangerous_permissions) - 5} more")
    print()

    # Analyze first few users
    print("2. Analyzing IAM users...")
    users = scanner.list_users()
    print(f"   Found {len(users)} users\n")

    for user in users[:3]:  # Analyze first 3 users
        print(f"   User: {user.name}")
        analysis = analyzer.analyze_user_permissions(user)

        print(f"      Permission Level: {analysis.permission_level}")
        print(f"      Admin Access: {analysis.admin_access}")
        print(f"      Policies: {len(analysis.attached_policies)} attached, {len(analysis.inline_policies)} inline")
        print(f"      Groups: {len(analysis.group_memberships)}")

        if analysis.dangerous_permissions:
            print(f"      ⚠️  Dangerous: {len(analysis.dangerous_permissions)} permissions")

        # Show resource access summary
        if analysis.resource_access:
            print(f"      Resource Access:")
            for service, resources in list(analysis.resource_access.items())[:3]:
                print(f"         - {service}: {len(resources)} resource(s)")

        print()

    # Analyze first few roles
    print("3. Analyzing IAM roles (sample)...")
    roles = scanner.list_roles()
    print(f"   Found {len(roles)} roles\n")

    for role in roles[:3]:  # Analyze first 3 roles
        print(f"   Role: {role.name}")
        analysis = analyzer.analyze_role_permissions(role)

        print(f"      Permission Level: {analysis.permission_level}")
        print(f"      Admin Access: {analysis.admin_access}")
        print(f"      Policies: {len(analysis.attached_policies)} attached, {len(analysis.inline_policies)} inline")

        if analysis.dangerous_permissions:
            print(f"      ⚠️  Dangerous: {len(analysis.dangerous_permissions)} permissions")

        print()

    print("=== Analysis Complete ===")


if __name__ == "__main__":
    main()
