#Simple mcp server configuation
from fastmcp import FastMCP
from glob import glob

mcp = FastMCP("MCP")

# Prompt
@mcp.prompt()
def spell_check(text: str) -> str:
    """Generates a user message asking for a spell check of an input text."""
    return f"Please check the following text for typos and grammatical errors:\n\n{text}" 

# Resource
@mcp.resource("resource://filecount")
def count_files() -> int:
    """Provides the number of stored files."""
    return len(glob("/tmp/*.mcpfile"))

# Resource Template
@mcp.resource("getfile://{file_name}")
def get_file(file_name: str) -> str:
    """Get content of a stored file."""
    with open(f"/tmp/{file_name}.mcpfile", "r") as f:
        return f.read()
 
# Tool
@mcp.tool()
def store_file(file_content: str, file_name: str) -> str:
    """Store a file."""
    with open(f"/tmp/{file_name}.mcpfile", "w+") as f:
        f.write(file_content)
    return file_content

mcp.run(transport="streamable-http", host="127.0.0.1", port=8000)
