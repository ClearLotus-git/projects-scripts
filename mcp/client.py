import asyncio
from fastmcp import Client, FastMCP

client = Client("http://localhost:8000/mcp/")

async def main():
    async with client:
        resources = await client.list_resources()
        result_object = await client.read_resource("resource://filecount")
        result_text = result_object[0].text

        print(f"*** Available Resources:\n{resources}\n*** Resource Result:\n{result_text}\n")

        resource_templates = await client.list_resource_templates()
        result_object = await client.read_resource("getfile://helloworld")
        result_text = result_object[0].text

        print(f"*** Available Resource Templates:\n{resource_templates}\n*** Resource Template Result:\n{result_text}\n")

asyncio.run(main())
