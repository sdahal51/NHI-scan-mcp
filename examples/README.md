# NHI Scan MCP Examples

This directory contains example scripts demonstrating how to use the NHI Scan MCP library directly in Python (without the MCP server).

## Examples

### 1. basic_scan.py

Basic IAM scanning and NHI identification.

**What it demonstrates:**
- Connecting to AWS IAM
- Listing all users and roles
- Identifying Non-Human Identities
- Viewing NHI categories and confidence scores

**Run:**
```bash
python examples/basic_scan.py
```

### 2. permission_analysis.py

Detailed permission analysis for IAM identities.

**What it demonstrates:**
- Analyzing your own (caller's) permissions
- Examining user and role permissions
- Identifying dangerous permissions
- Understanding permission levels (admin, power user, read-write, etc.)

**Run:**
```bash
python examples/permission_analysis.py
```

### 3. user_vs_nhi.py

Distinguishing between human users and non-human identities.

**What it demonstrates:**
- Separating human users from NHIs
- Identifying uncertain users that need review
- Generating security recommendations
- Analyzing role categories

**Run:**
```bash
python examples/user_vs_nhi.py
```

## Prerequisites

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Configure AWS credentials:
   - Option 1: Environment variables
     ```bash
     export AWS_ACCESS_KEY_ID=your_key
     export AWS_SECRET_ACCESS_KEY=your_secret
     ```
   - Option 2: AWS credentials file (~/.aws/credentials)
   - Option 3: IAM role (if running on EC2/ECS)

3. Ensure your AWS credentials have the required IAM read permissions (see main README.md)

## Running the Examples

All examples use the default AWS credential chain, so make sure your credentials are configured before running.

```bash
# Run from the project root directory
cd /path/to/NHI-scan-mcp

# Run any example
python examples/basic_scan.py
python examples/permission_analysis.py
python examples/user_vs_nhi.py
```

## Using as a Library

You can also use the modules directly in your own Python scripts:

```python
from nhi_scan_mcp.aws_scanner import AWSIAMScanner
from nhi_scan_mcp.nhi_identifier import NHIIdentifier
from nhi_scan_mcp.permission_analyzer import PermissionAnalyzer

# Initialize scanner
scanner = AWSIAMScanner()

# Scan IAM
users = scanner.list_users()
roles = scanner.list_roles()

# Identify NHIs
identifier = NHIIdentifier()
identifications = identifier.identify_all(users, roles)

# Analyze permissions
analyzer = PermissionAnalyzer(scanner)
for user in users:
    analysis = analyzer.analyze_user_permissions(user)
    print(f"{user.name}: {analysis.permission_level}")
```

## MCP Server Usage

To use these tools through the MCP server instead:

1. Start the server:
   ```bash
   python -m nhi_scan_mcp.server
   ```

2. Connect with an MCP client and call the tools (see main README.md for tool details)
