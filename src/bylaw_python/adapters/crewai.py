# Bylaw ALCV — CrewAI Adapter
# Wraps CrewAI tools with Vault clearance enforcement

from __future__ import annotations

from typing import Any, Type

from pydantic import BaseModel

from ..client import BylawClient
from ..exceptions import ClearanceDeniedError
from ._core import build_clearance_request, resolve_client

try:
    from crewai.tools import BaseTool as CrewAIBaseTool
except ImportError as exc:
    raise ImportError(
        "CrewAI adapter requires crewai. "
        "Install with: pip install bylaw-python[crewai]"
    ) from exc


class BylawCrewAITool(CrewAIBaseTool):
    """Wraps a CrewAI tool with Vault clearance enforcement.

    Usage with explicit client::

        from crewai.tools import BaseTool
        from bylaw_python.adapters.crewai import BylawCrewAITool

        guarded = BylawCrewAITool.wrap(client, MyTool())

    Usage after :func:`bylaw_python.configure`::

        guarded = BylawCrewAITool.wrap(MyTool())
    """

    name: str = ""
    description: str = ""
    _inner_tool: CrewAIBaseTool
    _client: BylawClient | None
    _policy_id: str | None

    class Config:
        arbitrary_types_allowed = True
        underscore_attrs_are_private = True

    def __init__(
        self,
        inner_tool: CrewAIBaseTool,
        client: BylawClient | None = None,
        *,
        policy_id: str | None = None,
    ) -> None:
        super().__init__(
            name=f"bylaw_{inner_tool.name}",
            description=inner_tool.description,
        )
        self._inner_tool = inner_tool
        self._client = client
        self._policy_id = policy_id

    def _resolve_client(self) -> BylawClient:
        return resolve_client(self._client)

    @classmethod
    def wrap(
        cls,
        client_or_tool: BylawClient | CrewAIBaseTool,
        tool: CrewAIBaseTool | None = None,
        *,
        policy_id: str | None = None,
    ) -> BylawCrewAITool:
        """Convenience factory to wrap a CrewAI tool.

        Supports two call signatures:

        - ``BylawCrewAITool.wrap(client, tool, policy_id=...)`` — explicit client
        - ``BylawCrewAITool.wrap(tool, policy_id=...)`` — uses global client from :func:`bylaw_python.configure`
        """
        if isinstance(client_or_tool, BylawClient):
            return cls(inner_tool=tool, client=client_or_tool, policy_id=policy_id)  # type: ignore[arg-type]
        return cls(inner_tool=client_or_tool, client=None, policy_id=policy_id)

    def _run(self, **kwargs: Any) -> Any:
        client = self._resolve_client()
        request = build_clearance_request(
            tool_name=self._inner_tool.name,
            tool_args=kwargs,
            client=client,
            policy_id=self._policy_id,
        )

        try:
            client.request_clearance(request)
        except ClearanceDeniedError as exc:
            return f"BLOCKED: Vault denied this action — {exc.reason}"

        return self._inner_tool._run(**kwargs)
