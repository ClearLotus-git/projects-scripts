import asyncio
from fastmcp import Client, FastMCP

client = Client("http://localhost:8000/mcp/")

async def main():
    async with client:
        prompts = await client.list_prompts()
        result_object = await client.get_prompt("spell_check", {"text": "Hello World!"})
        prompt_text = result_object.messages[0].content.text

        print(f"*** Available Prompts:\n{prompts}\n*** Prompt Result:\n{prompt_text}\n")

asyncio.run(main())
