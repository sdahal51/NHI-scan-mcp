# NHI Scan MCP

MCP server for scanning AWS IAM identities and identifying Non-Human Identities (NHIs) such as service accounts, automation users, and machine identities.

## Overview

This tool scans AWS IAM users and roles to distinguish between human users and non-human identities. It analyzes naming patterns, authentication methods, access keys, MFA configuration, and IAM tags to classify identities with a confidence score. Optionally includes detailed permission analysis to assess access levels and identify potentially dangerous permissions.

## Features

- Scans all IAM users and roles in an AWS account
- Classifies identities as human or non-human with confidence scoring
- Categorizes NHIs by type (service roles, machine users, Lambda execution roles, etc.)
- Optional permission analysis with access level assessment
- Identifies dangerous permissions and potential security risks

## Installation

### Requirements

- Python 3.10 or higher
- AWS credentials with IAM read permissions

### Setup

Clone the repository and install dependencies:

```bash
git clone https://github.com/yourusername/NHI-scan-mcp.git
cd NHI-scan-mcp
pip install -r requirements.txt
```

For development mode:
```bash
pip install -e .
```

## Usage

### Starting the Server

```bash
python -m nhi_scan_mcp.server
```

Alternatively:
```bash
python src/nhi_scan_mcp/server.py
```

### MCP Tools

The server exposes five tools for IAM scanning and analysis:

#### `scan_iam_identities`

Main scanning tool that lists all IAM identities, classifies NHIs, and optionally analyzes permissions.

**Parameters:**
- `aws_access_key_id` (string, optional) - AWS access key ID
- `aws_secret_access_key` (string, optional) - AWS secret access key
- `aws_session_token` (string, optional) - Session token for temporary credentials
- `region` (string, optional) - AWS region, defaults to us-east-1
- `include_permissions` (boolean, optional) - Include permission analysis, defaults to false

**Example:**
```json
{
  "aws_access_key_id": "AKIA...",
  "aws_secret_access_key": "...",
  "region": "us-west-2",
  "include_permissions": true
}
```

**Returns:** Complete scan results including all identities, NHI classifications, confidence scores, and optional permission analysis.

#### `list_nhi_identities`

Returns only non-human identities filtered by confidence threshold.

**Parameters:**
- `aws_access_key_id` (string, optional)
- `aws_secret_access_key` (string, optional)
- `aws_session_token` (string, optional)
- `region` (string, optional)
- `min_confidence` (float, optional) - Minimum confidence threshold (0.0-1.0), defaults to 0.5

**Returns:** Filtered list of NHIs meeting the confidence threshold with classification details.

#### `analyze_caller_permissions`

Analyzes permissions for the AWS credentials being used to run the scan.

**Parameters:**
- `aws_access_key_id` (string, optional)
- `aws_secret_access_key` (string, optional)
- `aws_session_token` (string, optional)
- `region` (string, optional)

**Returns:** Permission analysis for the caller including access level and dangerous permissions.

#### `get_identity_details`

Retrieves detailed information for a specific IAM user or role.

**Parameters:**
- `identity_name` (string, required) - Name of the IAM user or role
- `identity_type` (string, optional) - Either "user" or "role", defaults to user
- `aws_access_key_id` (string, optional)
- `aws_secret_access_key` (string, optional)
- `aws_session_token` (string, optional)
- `region` (string, optional)

**Returns:** Complete identity details including NHI classification and permission analysis.

#### `distinguish_users_vs_nhi`

Provides a breakdown separating human users from non-human identities with statistics and recommendations.

**Parameters:**
- `aws_access_key_id` (string, optional)
- `aws_secret_access_key` (string, optional)
- `aws_session_token` (string, optional)
- `region` (string, optional)

**Returns:** Summary statistics, user lists by category, and security recommendations.

### AWS Credentials

Credentials can be provided in the following order of precedence:

1. Explicit parameters (`aws_access_key_id`, `aws_secret_access_key`)
2. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
3. AWS credentials file (`~/.aws/credentials`)
4. IAM role (when running on EC2/ECS)

### Required IAM Permissions

The AWS credentials must have the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListUserTags",
        "iam:ListRoleTags",
        "iam:ListAccessKeys",
        "iam:ListMFADevices",
        "iam:GetUser",
        "iam:GetRole",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListUserPolicies",
        "iam:ListRolePolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:GetUserPolicy",
        "iam:GetRolePolicy",
        "iam:ListGroupsForUser",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## NHI Identification Methodology

### IAM Users

The tool evaluates multiple signals to determine if a user is non-human:

- **Name patterns** - Matches against common prefixes like `svc-`, `app-`, `bot-`, `api-`, `lambda-`, `ci-`, `cd-`, `terraform-`, `ansible-`, etc.
- **Password usage** - Users with no password login history
- **Access keys** - Presence of active programmatic access keys
- **MFA status** - Absence of MFA devices (expected for human users)
- **Tags** - Explicit tags marking service accounts, bots, or automation

Each signal contributes to a confidence score from 0.0 to 1.0. Users with confidence ≥ 0.5 are classified as NHIs.

### IAM Roles

All roles are inherently non-human, but are further classified by analyzing their assume role policy:

- **Service roles** - Trusted by AWS services (Lambda, EC2, ECS, etc.)
- **Lambda execution roles** - Specifically for Lambda functions
- **EC2 instance profiles** - For EC2 instances
- **Cross-account roles** - Trust relationships with other AWS accounts
- **Federated roles** - SAML or OIDC federation
- **Application roles** - General application service roles

## Examples

Example scripts are available in the `examples/` directory:

- `basic_scan.py` - Basic IAM scanning and NHI identification
- `permission_analysis.py` - Detailed permission analysis
- `user_vs_nhi.py` - Distinguishing human users from NHIs

## License

MIT License - see LICENSE file for details.

## Acknowledgments

Built with [FastMCP](https://github.com/jlowin/fastmcp) for Model Context Protocol server implementation and [boto3](https://github.com/boto/boto3) for AWS API interactions.
