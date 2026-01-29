"""
Example demonstrating distinguishing between human users and NHIs.

This example shows:
1. Separating human users from non-human identities
2. Generating security recommendations
3. Creating actionable summaries
"""

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.nhi_scan_mcp.aws_scanner import AWSIAMScanner
from src.nhi_scan_mcp.nhi_identifier import NHIIdentifier


def main():
    """Distinguish human users from NHIs."""
    print("=== Human Users vs Non-Human Identities ===\n")

    # Initialize scanner
    scanner = AWSIAMScanner()

    # Get caller identity
    caller = scanner.get_caller_identity()
    print(f"Account: {caller['Account']}\n")

    # Scan IAM
    print("Scanning IAM...")
    users = scanner.list_users()
    roles = scanner.list_roles()
    print(f"Found {len(users)} users and {len(roles)} roles\n")

    # Identify all identities
    identifier = NHIIdentifier()
    identifications = identifier.identify_all(users, roles)

    # Separate by type
    human_users = []
    nhi_users = []
    uncertain_users = []

    for identification in identifications:
        if identification.identity.identity_type != "user":
            continue

        if identification.nhi_category.value == "human_user":
            human_users.append(identification)
        elif identification.nhi_category.value == "uncertain":
            uncertain_users.append(identification)
        else:
            nhi_users.append(identification)

    # Display human users
    print("=" * 60)
    print("HUMAN USERS")
    print("=" * 60)
    print(f"Total: {len(human_users)}\n")

    for identification in human_users:
        user = identification.identity
        print(f"👤 {user.name}")
        print(f"   ARN: {user.arn}")
        print(f"   Has MFA: {'✓' if user.mfa_devices else '✗'}")
        print(f"   Last Password Use: {user.password_last_used or 'Never'}")
        print(f"   Active Keys: {sum(1 for k in user.access_keys if k['Status'] == 'Active')}")
        print()

    # Display NHI users
    print("=" * 60)
    print("NON-HUMAN IDENTITY USERS")
    print("=" * 60)
    print(f"Total: {len(nhi_users)}\n")

    for identification in nhi_users:
        user = identification.identity
        print(f"🤖 {user.name}")
        print(f"   ARN: {user.arn}")
        print(f"   Category: {identification.nhi_category}")
        print(f"   Confidence: {identification.confidence:.2f}")
        print(f"   Reasons:")
        for reason in identification.reasons:
            print(f"      - {reason}")
        print()

    # Display uncertain users
    if uncertain_users:
        print("=" * 60)
        print("UNCERTAIN USERS (Need Review)")
        print("=" * 60)
        print(f"Total: {len(uncertain_users)}\n")

        for identification in uncertain_users:
            user = identification.identity
            print(f"❓ {user.name}")
            print(f"   ARN: {user.arn}")
            print(f"   Confidence: {identification.confidence:.2f}")
            if identification.reasons:
                print(f"   Indicators:")
                for reason in identification.reasons:
                    print(f"      - {reason}")
            print()

    # Role summary
    role_identifications = [i for i in identifications if i.identity.identity_type == "role"]
    print("=" * 60)
    print("IAM ROLES (All Non-Human)")
    print("=" * 60)
    print(f"Total: {len(role_identifications)}\n")

    role_categories = {}
    for identification in role_identifications:
        cat = str(identification.nhi_category)
        role_categories[cat] = role_categories.get(cat, 0) + 1

    for category, count in sorted(role_categories.items(), key=lambda x: -x[1]):
        print(f"  {category}: {count}")
    print()

    # Security recommendations
    print("=" * 60)
    print("SECURITY RECOMMENDATIONS")
    print("=" * 60)

    recommendations = []

    # Check for users without MFA
    no_mfa_humans = [i for i in human_users if not i.identity.mfa_devices]
    if no_mfa_humans:
        recommendations.append(
            f"⚠️  {len(no_mfa_humans)} human user(s) lack MFA - enable MFA immediately"
        )
        for i in no_mfa_humans:
            recommendations.append(f"     - {i.identity.name}")

    # Check for NHI users that should be roles
    if nhi_users:
        recommendations.append(
            f"💡 Consider migrating {len(nhi_users)} NHI user(s) to IAM roles for better security:"
        )
        for i in nhi_users[:5]:  # Show first 5
            recommendations.append(f"     - {i.identity.name}")
        if len(nhi_users) > 5:
            recommendations.append(f"     ... and {len(nhi_users) - 5} more")

    # Check for uncertain users
    if uncertain_users:
        recommendations.append(
            f"🔍 Review {len(uncertain_users)} uncertain user(s) - add proper tagging or naming:"
        )
        for i in uncertain_users:
            recommendations.append(f"     - {i.identity.name}")

    # Check for users with never-used passwords
    never_logged_in = [
        i
        for i in human_users
        if i.identity.password_last_used is None
    ]
    if never_logged_in:
        recommendations.append(
            f"🔒 {len(never_logged_in)} human user(s) have never logged in - verify they're needed"
        )

    # Print recommendations
    for rec in recommendations:
        print(rec)

    if not recommendations:
        print("✓ No immediate security concerns detected")

    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
