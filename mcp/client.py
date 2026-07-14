import asyncio
from fastmcp import Client, FastMCP

client = Client("http://localhost:8000/mcp/")

async def main():
    async with client:
        tools = await client.list_tools()
        result_object = await client.call_tool("store_file", {"file_content": "Hello World!", "file_name": "helloworld"})
        result_text = result_object.content[0].text

        print(f"*** Available Tools:\n{tools}\n*** Tool Result:\n{result_text}\n")

asyncio.run(main())
