"""
Basic example of scanning IAM identities and identifying NHIs.

This example demonstrates:
1. Setting up AWS credentials
2. Scanning all IAM users and roles
3. Identifying Non-Human Identities
"""

import json
import os
import sys

# Add parent directory to path to import the module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.nhi_scan_mcp.aws_scanner import AWSIAMScanner
from src.nhi_scan_mcp.nhi_identifier import NHIIdentifier


def main():
    """Run basic IAM scan and NHI identification."""
    print("=== AWS IAM NHI Scanner - Basic Example ===\n")

    # Initialize scanner (uses default AWS credential chain)
    # You can also pass explicit credentials:
    # scanner = AWSIAMScanner(
    #     aws_access_key_id="YOUR_KEY",
    #     aws_secret_access_key="YOUR_SECRET",
    #     region_name="us-east-1"
    # )
    scanner = AWSIAMScanner()

    # Get caller identity
    print("1. Getting caller identity...")
    caller = scanner.get_caller_identity()
    print(f"   Account: {caller['Account']}")
    print(f"   ARN: {caller['Arn']}")
    print()

    # List all IAM users
    print("2. Scanning IAM users...")
    users = scanner.list_users()
    print(f"   Found {len(users)} users")
    print()

    # List all IAM roles
    print("3. Scanning IAM roles...")
    roles = scanner.list_roles()
    print(f"   Found {len(roles)} roles")
    print()

    # Identify NHIs
    print("4. Identifying Non-Human Identities...")
    identifier = NHIIdentifier()
    identifications = identifier.identify_all(users, roles)
    print()

    # Display results
    print("=== NHI Identification Results ===\n")

    # Users
    print("IAM Users:")
    user_identifications = [i for i in identifications if i.identity.identity_type == "user"]
    for identification in user_identifications:
        icon = "🤖" if identification.is_nhi else "👤"
        print(f"{icon} {identification.identity.name}")
        print(f"   Category: {identification.nhi_category}")
        print(f"   Confidence: {identification.confidence:.2f}")
        if identification.reasons:
            print(f"   Reasons:")
            for reason in identification.reasons:
                print(f"     - {reason}")
        print()

    # Roles (summary only, as there may be many)
    print(f"\nIAM Roles: {len(roles)} total")
    role_identifications = [i for i in identifications if i.identity.identity_type == "role"]

    # Count by category
    role_categories = {}
    for identification in role_identifications:
        cat = str(identification.nhi_category)
        role_categories[cat] = role_categories.get(cat, 0) + 1

    print("Role categories:")
    for category, count in sorted(role_categories.items()):
        print(f"  - {category}: {count}")
    print()

    # Summary
    summary = identifier.summarize_identifications(identifications)
    print("=== Summary ===")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
