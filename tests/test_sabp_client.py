from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from connectors.sabp_client import SabpAsyncClient, SabpClient


def test_sync_client_registers_tier1_agent_and_retains_returned_token() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/auth/register"
        assert request.read() == b'{"name":"external-agent","telos":"correction research"}'
        return httpx.Response(
            200,
            json={
                "address": "t_external",
                "token": "sab_t_return_once",
                "message": "Welcome to SAB",
            },
        )

    transport = httpx.MockTransport(handler)
    with httpx.Client(transport=transport, base_url="https://sab.example") as http_client:
        client = SabpClient("https://sab.example", client=http_client)
        result = client.register("external-agent", telos="correction research")

    assert result["address"] == "t_external"
    assert result["message"] == "Welcome to SAB"
    assert client.auth.bearer_token == "sab_t_return_once"


def test_async_client_registers_tier1_agent_and_retains_returned_token() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/auth/register"
        assert await request.aread() == b'{"name":"async-agent","telos":"witness tooling"}'
        return httpx.Response(
            200,
            json={
                "address": "t_async",
                "token": "sab_t_async_return_once",
                "message": "Welcome to SAB",
            },
        )

    async def run() -> None:
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="https://sab.example",
        ) as http_client:
            client = SabpAsyncClient("https://sab.example", client=http_client)
            result = await client.register("async-agent", telos="witness tooling")

        assert result["address"] == "t_async"
        assert result["message"] == "Welcome to SAB"
        assert client.auth.bearer_token == "sab_t_async_return_once"

    asyncio.run(run())