# Ledgix ALCV — CrewAI Adapter
# Wraps CrewAI tools with Vault clearance enforcement

from __future__ import annotations

from typing import Any, Type

from pydantic import BaseModel

from ..client import LedgixClient
from ..enforce import _get_default_client
from ..exceptions import ClearanceDeniedError
from ..models import ClearanceRequest

try:
    from crewai.tools import BaseTool as CrewAIBaseTool
except ImportError as exc:
    raise ImportError(
        "CrewAI adapter requires crewai. "
        "Install with: pip install ledgix-python[crewai]"
    ) from exc


class LedgixCrewAITool(CrewAIBaseTool):
    """Wraps a CrewAI tool with Vault clearance enforcement.

    Usage with explicit client::

        from crewai.tools import BaseTool
        from ledgix_python.adapters.crewai import LedgixCrewAITool

        guarded = LedgixCrewAITool.wrap(client, MyTool())

    Usage after :func:`ledgix_python.configure`::

        guarded = LedgixCrewAITool.wrap(MyTool())
    """

    name: str = ""
    description: str = ""
    _inner_tool: CrewAIBaseTool
    _client: LedgixClient | None
    _policy_id: str | None

    class Config:
        arbitrary_types_allowed = True
        underscore_attrs_are_private = True

    def __init__(
        self,
        inner_tool: CrewAIBaseTool,
        client: LedgixClient | None = None,
        *,
        policy_id: str | None = None,
    ) -> None:
        super().__init__(
            name=f"ledgix_{inner_tool.name}",
            description=inner_tool.description,
        )
        self._inner_tool = inner_tool
        self._client = client
        self._policy_id = policy_id

    def _resolve_client(self) -> LedgixClient:
        return self._client if self._client is not None else _get_default_client()

    @classmethod
    def wrap(
        cls,
        client_or_tool: LedgixClient | CrewAIBaseTool,
        tool: CrewAIBaseTool | None = None,
        *,
        policy_id: str | None = None,
    ) -> LedgixCrewAITool:
        """Convenience factory to wrap a CrewAI tool.

        Supports two call signatures:

        - ``LedgixCrewAITool.wrap(client, tool, policy_id=...)`` — explicit client
        - ``LedgixCrewAITool.wrap(tool, policy_id=...)`` — uses global client from :func:`ledgix_python.configure`
        """
        if isinstance(client_or_tool, LedgixClient):
            return cls(inner_tool=tool, client=client_or_tool, policy_id=policy_id)  # type: ignore[arg-type]
        return cls(inner_tool=client_or_tool, client=None, policy_id=policy_id)

    def _run(self, **kwargs: Any) -> Any:
        client = self._resolve_client()
        ctx: dict[str, Any] = {}
        if self._policy_id:
            ctx["policy_id"] = self._policy_id

        request = ClearanceRequest(
            tool_name=self._inner_tool.name,
            tool_args=kwargs,
            agent_id=client.config.agent_id,
            session_id=client.config.session_id,
            context=ctx,
        )

        try:
            client.request_clearance(request)
        except ClearanceDeniedError as exc:
            return f"BLOCKED: Vault denied this action — {exc.reason}"

        return self._inner_tool._run(**kwargs)
