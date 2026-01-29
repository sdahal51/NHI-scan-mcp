"""Entry point for running the NHI Scan MCP server."""

from .server import mcp

if __name__ == "__main__":
    mcp.run()
