# Quick Start Guide

Get started with NHI Scan MCP in minutes!

## Installation

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Configure AWS credentials (choose one method):

   **Option A: Environment variables**
   ```bash
   export AWS_ACCESS_KEY_ID=your_access_key
   export AWS_SECRET_ACCESS_KEY=your_secret_key
   export AWS_DEFAULT_REGION=us-east-1
   ```

   **Option B: AWS credentials file**
   ```bash
   aws configure
   ```

   **Option C: Use existing AWS session**
   (If already configured, the tool will use your default credentials)

## Quick Test

Run the basic scan example to verify everything works:

```bash
python examples/basic_scan.py
```

This will:
- Connect to AWS using your credentials
- List all IAM users and roles
- Identify Non-Human Identities
- Display results with confidence scores

## Running as MCP Server

### Method 1: Direct Python execution

```bash
python -m nhi_scan_mcp.server
```

### Method 2: Using the source path

```bash
python src/nhi_scan_mcp/server.py
```

### Method 3: With MCP client configuration

Add to your MCP client config (e.g., Claude Desktop):

```json
{
  "mcpServers": {
    "nhi-scan": {
      "command": "python",
      "args": ["-m", "nhi_scan_mcp.server"],
      "cwd": "/path/to/NHI-scan-mcp",
      "env": {
        "AWS_REGION": "us-east-1"
      }
    }
  }
}
```

## Available MCP Tools

Once the server is running, you can use these tools:

1. **scan_iam_identities** - Complete IAM scan with NHI identification
2. **list_nhi_identities** - List only Non-Human Identities
3. **analyze_caller_permissions** - Analyze your credential's permissions
4. **get_identity_details** - Get details for a specific user/role
5. **distinguish_users_vs_nhi** - Separate humans from NHIs with recommendations

## Example Usage

### Scan all IAM identities

```python
# In your MCP client, call the tool:
scan_iam_identities(
    region="us-east-1",
    include_permissions=True
)
```

### List only NHIs with high confidence

```python
list_nhi_identities(
    min_confidence=0.7,
    region="us-east-1"
)
```

### Analyze your own permissions

```python
analyze_caller_permissions(
    region="us-east-1"
)
```

### Get user/NHI distinction with recommendations

```python
distinguish_users_vs_nhi(
    region="us-east-1"
)
```

## Running Example Scripts

Try all the examples:

```bash
# Basic IAM scanning
python examples/basic_scan.py

# Permission analysis
python examples/permission_analysis.py

# User vs NHI distinction
python examples/user_vs_nhi.py
```

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Check out [examples/README.md](examples/README.md) for more examples
- Review [CONTRIBUTING.md](CONTRIBUTING.md) if you want to contribute
- Explore the code in `src/nhi_scan_mcp/` to understand the implementation

## Troubleshooting

### "No credentials found"
- Ensure AWS credentials are configured (see Installation step 2)
- Try: `aws sts get-caller-identity` to verify AWS CLI works

### "Access Denied" errors
- Ensure your IAM user/role has the required permissions
- See README.md for the complete IAM policy needed

### Import errors
- Ensure dependencies are installed: `pip install -r requirements.txt`
- Try installing in development mode: `pip install -e .`

### MCP server not connecting
- Verify the server starts without errors
- Check the command path in your MCP client config
- Ensure Python is in your PATH

## Need Help?

- Open an issue on GitHub
- Check existing issues for similar problems
- Review the full documentation in README.md
