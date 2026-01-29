# NHI Scan MCP

An MCP (Model Context Protocol) server for scanning AWS IAM credentials and identifying Non-Human Identities (NHIs) in your AWS account.

## Features

- **IAM Scanning**: Automatically discovers all IAM users and roles in your AWS account
- **NHI Identification**: Intelligently classifies identities as human users or non-human identities (service accounts, bots, automation users, etc.)
- **Permission Analysis**: Analyzes IAM permissions to determine access levels and identify dangerous permissions
- **Comprehensive Classification**: Categorizes NHIs into specific types:
  - Service Roles (Lambda, EC2, ECS, etc.)
  - Machine Users
  - Application Roles
  - Cross-Account Roles
  - Federated Roles
  - And more...
- **User vs NHI Distinction**: Provides detailed breakdown and recommendations for human vs non-human identities

## Installation

### Prerequisites

- Python 3.10 or higher
- AWS credentials with IAM read permissions

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/NHI-scan-mcp.git
cd NHI-scan-mcp
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

Or install in development mode:
```bash
pip install -e .
```

## Usage

### Running as an MCP Server

Start the MCP server:

```bash
python -m nhi_scan_mcp.server
```

Or use the direct path:

```bash
python src/nhi_scan_mcp/server.py
```

### Available MCP Tools

The server exposes the following tools that can be called by MCP clients:

#### 1. `scan_iam_identities`

Comprehensive scan of all IAM identities with NHI classification and optional permission analysis.

**Parameters:**
- `aws_access_key_id` (optional): AWS access key ID
- `aws_secret_access_key` (optional): AWS secret access key
- `aws_session_token` (optional): AWS session token for temporary credentials
- `region` (optional): AWS region (default: us-east-1)
- `include_permissions` (optional): Include detailed permission analysis (default: false)

**Example:**
```json
{
  "aws_access_key_id": "AKIA...",
  "aws_secret_access_key": "...",
  "region": "us-west-2",
  "include_permissions": true
}
```

#### 2. `list_nhi_identities`

List all identified Non-Human Identities with filtering by confidence level.

**Parameters:**
- `aws_access_key_id` (optional): AWS access key ID
- `aws_secret_access_key` (optional): AWS secret access key
- `aws_session_token` (optional): AWS session token
- `region` (optional): AWS region (default: us-east-1)
- `min_confidence` (optional): Minimum confidence threshold (0.0-1.0, default: 0.5)

#### 3. `analyze_caller_permissions`

Analyze the permissions of the current AWS credentials.

**Parameters:**
- `aws_access_key_id` (optional): AWS access key ID
- `aws_secret_access_key` (optional): AWS secret access key
- `aws_session_token` (optional): AWS session token
- `region` (optional): AWS region (default: us-east-1)

#### 4. `get_identity_details`

Get detailed information about a specific IAM identity.

**Parameters:**
- `identity_name` (required): Name of the IAM user or role
- `identity_type` (optional): "user" or "role" (default: user)
- `aws_access_key_id` (optional): AWS access key ID
- `aws_secret_access_key` (optional): AWS secret access key
- `aws_session_token` (optional): AWS session token
- `region` (optional): AWS region (default: us-east-1)

#### 5. `distinguish_users_vs_nhi`

Distinguish between human users and non-human identities with detailed summary and recommendations.

**Parameters:**
- `aws_access_key_id` (optional): AWS access key ID
- `aws_secret_access_key` (optional): AWS secret access key
- `aws_session_token` (optional): AWS session token
- `region` (optional): AWS region (default: us-east-1)

### AWS Credentials

The tools support multiple ways to provide AWS credentials:

1. **Explicit credentials**: Pass `aws_access_key_id` and `aws_secret_access_key` parameters
2. **Default credential chain**: If credentials are not provided, the tools will use:
   - Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
   - AWS credentials file (`~/.aws/credentials`)
   - IAM role (if running on EC2/ECS)

### Required IAM Permissions

The AWS credentials used must have the following IAM permissions:

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

## How NHI Identification Works

The tool uses multiple signals to identify Non-Human Identities:

### For IAM Users:

1. **Name Patterns**: Matches against common NHI naming conventions (e.g., `svc-`, `app-`, `bot-`, `api-`)
2. **Password Usage**: Users who have never logged in with a password
3. **Access Keys**: Presence of programmatic access keys
4. **MFA Status**: Lack of MFA devices (human users should have MFA)
5. **Tags**: Explicit tags indicating service accounts or automation

### For IAM Roles:

All roles are considered NHIs by definition, but are further classified into:

- **Service Roles**: Roles assumed by AWS services (Lambda, EC2, etc.)
- **Lambda Execution Roles**: Specifically for Lambda functions
- **EC2 Instance Profiles**: For EC2 instances
- **Cross-Account Roles**: Roles that trust other AWS accounts
- **Federated Roles**: Roles for SAML/OIDC federation
- **Application Roles**: General application service roles

## Examples

See the `examples/` directory for complete usage examples:

- `basic_scan.py`: Basic IAM scanning and NHI identification
- `permission_analysis.py`: Detailed permission analysis
- `user_vs_nhi.py`: Distinguishing human users from NHIs

## Security Best Practices

1. **Credential Management**: Use IAM roles when possible instead of long-term credentials
2. **Least Privilege**: Grant only the minimum required IAM permissions
3. **MFA**: Enable MFA for all human users
4. **NHI Migration**: Consider migrating NHI users to IAM roles for better security
5. **Regular Audits**: Regularly scan your IAM identities to identify and clean up unused accounts

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with [FastMCP](https://github.com/jlowin/fastmcp) for the Model Context Protocol server
- Uses [boto3](https://github.com/boto/boto3) for AWS API interactions
