"""Verifies that every MCP tool registered on the server has a docstring."""
import asyncio
import sys

sys.path.insert(0, "src")

from wazuh_mcp.server import mcp


async def main() -> int:
    tools = await mcp.list_tools()
    missing = [t.name for t in tools if not t.description]
    if missing:
        print(f"Tools sin docstring ({len(missing)}):")
        for name in missing:
            print(f"  - {name}")
        return 1
    print(f"OK: todas las tools tienen docstring ({len(tools)} tools)")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
