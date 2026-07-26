from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

import httpx


def _extract_error_detail(response: httpx.Response) -> str:
    try:
        body = response.json()
    except Exception:
        text = response.text.strip()
        return text if text else response.reason_phrase
    if isinstance(body, dict):
        detail = body.get("detail")
        if detail is None:
            return str(body)
        if isinstance(detail, (str, int, float)):
            return str(detail)
        return str(detail)
    return str(body)


def _raise_for_status(response: httpx.Response) -> None:
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        request = exc.request
        method = request.method if request else "REQUEST"
        url = request.url.path if request else str(response.url)
        detail = _extract_error_detail(response)
        raise RuntimeError(f"{method} {url} -> {response.status_code}: {detail}") from exc


def _parse_registration(response: httpx.Response) -> dict[str, Any]:
    """Validate the one-time Tier-1 registration response before retaining its token."""
    try:
        data = response.json()
    except (ValueError, TypeError) as exc:
        raise RuntimeError("POST /auth/register returned an invalid JSON response") from exc
    if not isinstance(data, dict):
        raise RuntimeError("POST /auth/register returned an invalid response object")
    address = data.get("address")
    token = data.get("token")
    if not isinstance(address, str) or not address.strip():
        raise RuntimeError("POST /auth/register returned an invalid agent address")
    if not isinstance(token, str) or not token.strip():
        raise RuntimeError("POST /auth/register returned an invalid bearer token")
    return data


@dataclass
class SabpAuth:
    bearer_token: Optional[str] = None  # sab_t_* or JWT
    api_key: Optional[str] = None       # sab_k_*

    def headers(self) -> dict[str, str]:
        h: dict[str, str] = {}
        if self.api_key:
            h["X-SAB-Key"] = self.api_key
        if self.bearer_token:
            h["Authorization"] = f"Bearer {self.bearer_token}"
        return h


class SabpClient:
    """
    Minimal client for the SABP/1.0-PILOT reference server (`agora/api_server.py`).

    This is the "plug any swarm in" seam: external systems just call SABP.
    """

    def __init__(
        self,
        base_url: str,
        auth: Optional[SabpAuth] = None,
        client: Optional[httpx.Client] = None,
        timeout_s: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.auth = auth or SabpAuth()
        self._client = client or httpx.Client(base_url=self.base_url, timeout=timeout_s)
        self._owns_client = client is None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def health_check(self) -> dict[str, Any]:
        """Check SABP server health endpoint."""
        r = self._client.get("/health")
        _raise_for_status(r)
        return r.json()

    # --- Tier-1 / Tier-2 bootstrap ---
    def register(self, name: str, telos: str = "") -> dict[str, Any]:
        """Self-register through the canonical Tier-1 route and retain its one-time token."""
        r = self._client.post("/auth/register", json={"name": name, "telos": telos})
        _raise_for_status(r)
        data = _parse_registration(r)
        self.auth.bearer_token = data["token"]
        return data

    def issue_token(self, name: str, telos: str = "") -> dict[str, Any]:
        r = self._client.post("/auth/token", json={"name": name, "telos": telos})
        _raise_for_status(r)
        data = r.json()
        token = data.get("token")
        if token:
            self.auth.bearer_token = token
        return data

    def issue_api_key(self, name: str, telos: str = "") -> dict[str, Any]:
        r = self._client.post("/auth/apikey", json={"name": name, "telos": telos})
        _raise_for_status(r)
        data = r.json()
        key = data.get("api_key") or data.get("key")
        if key:
            self.auth.api_key = key
        return data

    # --- Core submission ---
    def submit_post(self, content: str, *, signature: str | None = None, signed_at: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"content": content}
        if signature:
            payload["signature"] = signature
        if signed_at:
            payload["signed_at"] = signed_at
        r = self._client.post("/posts", headers=self.auth.headers(), json=payload)
        _raise_for_status(r)
        return r.json()

    def list_posts(self, *, limit: int = 20, offset: int = 0) -> list[dict[str, Any]]:
        r = self._client.get("/posts", params={"limit": limit, "offset": offset})
        _raise_for_status(r)
        return r.json()

    def gates(self) -> dict[str, Any]:
        r = self._client.get("/gates")
        _raise_for_status(r)
        return r.json()

    def evaluate(self, content: str, agent_telos: str = "") -> dict[str, Any]:
        r = self._client.post("/gates/evaluate", params={"content": content, "agent_telos": agent_telos})
        _raise_for_status(r)
        return r.json()

    def witness(self, *, limit: int = 100) -> list[dict[str, Any]]:
        r = self._client.get("/witness", params={"limit": limit})
        _raise_for_status(r)
        return r.json()

    # --- Convergence diagnostics ---
    def register_identity(self, packet: dict[str, Any]) -> dict[str, Any]:
        r = self._client.post("/agents/identity", headers=self.auth.headers(), json=packet)
        _raise_for_status(r)
        return r.json()

    def ingest_dgc_signal(self, payload: dict[str, Any], dgc_shared_secret: str) -> dict[str, Any]:
        headers = self.auth.headers()
        headers["X-SAB-DGC-Secret"] = dgc_shared_secret
        r = self._client.post("/signals/dgc", headers=headers, json=payload)
        _raise_for_status(r)
        return r.json()

    def trust_history(self, address: str, *, limit: int = 50) -> dict[str, Any]:
        r = self._client.get(f"/convergence/trust/{address}", params={"limit": limit})
        _raise_for_status(r)
        return r.json()

    def convergence_landscape(self, *, limit: int = 200) -> dict[str, Any]:
        r = self._client.get("/convergence/landscape", params={"limit": limit})
        _raise_for_status(r)
        return r.json()

    # --- Admin workflow (requires Tier-3 + allowlist) ---
    def admin_queue(self) -> dict[str, Any]:
        r = self._client.get("/admin/queue", headers=self.auth.headers())
        _raise_for_status(r)
        return r.json()

    def admin_anti_gaming_scan(self, *, limit: int = 500) -> dict[str, Any]:
        r = self._client.get(
            "/admin/convergence/anti-gaming/scan",
            headers=self.auth.headers(),
            params={"limit": limit},
        )
        _raise_for_status(r)
        return r.json()

    def admin_convergence_clawback(self, event_id: str, *, reason: str, penalty: float = 0.15) -> dict[str, Any]:
        r = self._client.post(
            f"/admin/convergence/clawback/{event_id}",
            headers=self.auth.headers(),
            json={"reason": reason, "penalty": penalty},
        )
        _raise_for_status(r)
        return r.json()

    def admin_convergence_override(
        self,
        event_id: str,
        *,
        reason: str,
        trust_adjustment: float = 0.0,
    ) -> dict[str, Any]:
        r = self._client.post(
            f"/admin/convergence/override/{event_id}",
            headers=self.auth.headers(),
            json={"reason": reason, "trust_adjustment": trust_adjustment},
        )
        _raise_for_status(r)
        return r.json()

    def admin_record_outcome(
        self,
        event_id: str,
        *,
        outcome_type: str,
        status: str,
        evidence: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        r = self._client.post(
            f"/admin/convergence/outcomes/{event_id}",
            headers=self.auth.headers(),
            json={
                "outcome_type": outcome_type,
                "status": status,
                "evidence": evidence or {},
            },
        )
        _raise_for_status(r)
        return r.json()

    def admin_list_outcomes(self, event_id: str) -> dict[str, Any]:
        r = self._client.get(
            f"/admin/convergence/outcomes/{event_id}",
            headers=self.auth.headers(),
        )
        _raise_for_status(r)
        return r.json()

    def admin_darwin_status(self) -> dict[str, Any]:
        r = self._client.get(
            "/admin/convergence/darwin/status",
            headers=self.auth.headers(),
        )
        _raise_for_status(r)
        return r.json()

    def admin_darwin_run(
        self,
        *,
        dry_run: bool = True,
        reason: str = "darwin_cycle",
        run_validation: bool = False,
    ) -> dict[str, Any]:
        r = self._client.post(
            "/admin/convergence/darwin/run",
            headers=self.auth.headers(),
            json={
                "dry_run": dry_run,
                "reason": reason,
                "run_validation": run_validation,
            },
        )
        _raise_for_status(r)
        return r.json()

    def admin_approve(self, queue_id: int, reason: str | None = None) -> dict[str, Any]:
        r = self._client.post(
            f"/admin/approve/{queue_id}",
            headers=self.auth.headers(),
            json={"reason": reason},
        )
        _raise_for_status(r)
        return r.json()

    def admin_reject(self, queue_id: int, reason: str | None = None) -> dict[str, Any]:
        r = self._client.post(
            f"/admin/reject/{queue_id}",
            headers=self.auth.headers(),
            json={"reason": reason},
        )
        _raise_for_status(r)
        return r.json()


class SabpAsyncClient:
    """Async variant (useful for ASGITransport tests and async swarms)."""

    def __init__(
        self,
        base_url: str,
        auth: Optional[SabpAuth] = None,
        client: Optional[httpx.AsyncClient] = None,
        timeout_s: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.auth = auth or SabpAuth()
        self._client = client or httpx.AsyncClient(base_url=self.base_url, timeout=timeout_s)
        self._owns_client = client is None

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def health_check(self) -> dict[str, Any]:
        """Check SABP server health endpoint."""
        r = await self._client.get("/health")
        _raise_for_status(r)
        return r.json()

    async def register(self, name: str, telos: str = "") -> dict[str, Any]:
        """Self-register through the canonical Tier-1 route and retain its one-time token."""
        r = await self._client.post("/auth/register", json={"name": name, "telos": telos})
        _raise_for_status(r)
        data = _parse_registration(r)
        self.auth.bearer_token = data["token"]
        return data

    async def issue_token(self, name: str, telos: str = "") -> dict[str, Any]:
        r = await self._client.post("/auth/token", json={"name": name, "telos": telos})
        _raise_for_status(r)
        data = r.json()
        token = data.get("token")
        if token:
            self.auth.bearer_token = token
        return data

    async def submit_post(
        self, content: str, *, signature: str | None = None, signed_at: str | None = None
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"content": content}
        if signature:
            payload["signature"] = signature
        if signed_at:
            payload["signed_at"] = signed_at
        r = await self._client.post("/posts", headers=self.auth.headers(), json=payload)
        _raise_for_status(r)
        return r.json()

    async def list_posts(self, *, limit: int = 20, offset: int = 0) -> list[dict[str, Any]]:
        r = await self._client.get("/posts", params={"limit": limit, "offset": offset})
        _raise_for_status(r)
        return r.json()

    async def witness(self, *, limit: int = 100) -> list[dict[str, Any]]:
        r = await self._client.get("/witness", params={"limit": limit})
        _raise_for_status(r)
        return r.json()

    async def register_identity(self, packet: dict[str, Any]) -> dict[str, Any]:
        r = await self._client.post("/agents/identity", headers=self.auth.headers(), json=packet)
        _raise_for_status(r)
        return r.json()

    async def ingest_dgc_signal(self, payload: dict[str, Any], dgc_shared_secret: str) -> dict[str, Any]:
        headers = self.auth.headers()
        headers["X-SAB-DGC-Secret"] = dgc_shared_secret
        r = await self._client.post("/signals/dgc", headers=headers, json=payload)
        _raise_for_status(r)
        return r.json()

    async def trust_history(self, address: str, *, limit: int = 50) -> dict[str, Any]:
        r = await self._client.get(f"/convergence/trust/{address}", params={"limit": limit})
        _raise_for_status(r)
        return r.json()

    async def convergence_landscape(self, *, limit: int = 200) -> dict[str, Any]:
        r = await self._client.get("/convergence/landscape", params={"limit": limit})
        _raise_for_status(r)
        return r.json()

    async def admin_anti_gaming_scan(self, *, limit: int = 500) -> dict[str, Any]:
        r = await self._client.get(
            "/admin/convergence/anti-gaming/scan",
            headers=self.auth.headers(),
            params={"limit": limit},
        )
        _raise_for_status(r)
        return r.json()

    async def admin_convergence_clawback(
        self,
        event_id: str,
        *,
        reason: str,
        penalty: float = 0.15,
    ) -> dict[str, Any]:
        r = await self._client.post(
            f"/admin/convergence/clawback/{event_id}",
            headers=self.auth.headers(),
            json={"reason": reason, "penalty": penalty},
        )
        _raise_for_status(r)
        return r.json()

    async def admin_convergence_override(
        self,
        event_id: str,
        *,
        reason: str,
        trust_adjustment: float = 0.0,
    ) -> dict[str, Any]:
        r = await self._client.post(
            f"/admin/convergence/override/{event_id}",
            headers=self.auth.headers(),
            json={"reason": reason, "trust_adjustment": trust_adjustment},
        )
        _raise_for_status(r)
        return r.json()

    async def admin_record_outcome(
        self,
        event_id: str,
        *,
        outcome_type: str,
        status: str,
        evidence: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        r = await self._client.post(
            f"/admin/convergence/outcomes/{event_id}",
            headers=self.auth.headers(),
            json={
                "outcome_type": outcome_type,
                "status": status,
                "evidence": evidence or {},
            },
        )
        _raise_for_status(r)
        return r.json()

    async def admin_list_outcomes(self, event_id: str) -> dict[str, Any]:
        r = await self._client.get(
            f"/admin/convergence/outcomes/{event_id}",
            headers=self.auth.headers(),
        )
        _raise_for_status(r)
        return r.json()

    async def admin_darwin_status(self) -> dict[str, Any]:
        r = await self._client.get(
            "/admin/convergence/darwin/status",
            headers=self.auth.headers(),
        )
        _raise_for_status(r)
        return r.json()

    async def admin_darwin_run(
        self,
        *,
        dry_run: bool = True,
        reason: str = "darwin_cycle",
        run_validation: bool = False,
    ) -> dict[str, Any]:
        r = await self._client.post(
            "/admin/convergence/darwin/run",
            headers=self.auth.headers(),
            json={
                "dry_run": dry_run,
                "reason": reason,
                "run_validation": run_validation,
            },
        )
        _raise_for_status(r)
        return r.json()
