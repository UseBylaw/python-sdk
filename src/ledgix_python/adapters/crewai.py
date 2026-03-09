# Ledgix ALCV — CrewAI Adapter
# Wraps CrewAI tools with Vault clearance enforcement

from __future__ import annotations

from typing import Any, Type

from pydantic import BaseModel

from ..client import LedgixClient
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

    Usage::

        from crewai.tools import BaseTool
        from ledgix_python.adapters.crewai import LedgixCrewAITool

        class MyTool(BaseTool):
            name = "search"
            description = "Search the web"

            def _run(self, query: str) -> str:
                return f"Results for {query}"

        guarded = LedgixCrewAITool.wrap(client, MyTool())
    """

    name: str = ""
    description: str = ""
    _inner_tool: CrewAIBaseTool
    _client: LedgixClient
    _policy_id: str | None

    class Config:
        arbitrary_types_allowed = True
        underscore_attrs_are_private = True

    def __init__(
        self,
        inner_tool: CrewAIBaseTool,
        client: LedgixClient,
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

    @classmethod
    def wrap(
        cls,
        client: LedgixClient,
        tool: CrewAIBaseTool,
        *,
        policy_id: str | None = None,
    ) -> LedgixCrewAITool:
        """Convenience factory to wrap a CrewAI tool."""
        return cls(inner_tool=tool, client=client, policy_id=policy_id)

    def _run(self, **kwargs: Any) -> Any:
        ctx: dict[str, Any] = {}
        if self._policy_id:
            ctx["policy_id"] = self._policy_id

        request = ClearanceRequest(
            tool_name=self._inner_tool.name,
            tool_args=kwargs,
            agent_id=self._client.config.agent_id,
            session_id=self._client.config.session_id,
            context=ctx,
        )

        try:
            self._client.request_clearance(request)
        except ClearanceDeniedError as exc:
            return f"BLOCKED: Vault denied this action — {exc.reason}"

        return self._inner_tool._run(**kwargs)
