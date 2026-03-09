# Ledgix ALCV — LangChain Adapter
# Provides a callback handler and tool wrapper for LangChain integration

from __future__ import annotations

from typing import Any

from ..client import LedgixClient
from ..exceptions import ClearanceDeniedError
from ..models import ClearanceRequest

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.tools import BaseTool, ToolException
except ImportError as exc:
    raise ImportError(
        "LangChain adapter requires langchain-core. "
        "Install with: pip install ledgix-python[langchain]"
    ) from exc


class LedgixCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that intercepts tool calls for Vault clearance.

    Usage::

        from ledgix_python.adapters.langchain import LedgixCallbackHandler

        handler = LedgixCallbackHandler(client)
        agent = create_agent(callbacks=[handler])
    """

    def __init__(self, client: LedgixClient, *, policy_id: str | None = None) -> None:
        self.client = client
        self.policy_id = policy_id

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Intercept tool start and request Vault clearance."""
        tool_name = serialized.get("name", "unknown_tool")
        tool_args = inputs or {"input": input_str}

        ctx: dict[str, Any] = {}
        if self.policy_id:
            ctx["policy_id"] = self.policy_id
        if metadata:
            ctx["langchain_metadata"] = metadata

        request = ClearanceRequest(
            tool_name=tool_name,
            tool_args=tool_args,
            agent_id=self.client.config.agent_id,
            session_id=self.client.config.session_id,
            context=ctx,
        )

        # This will raise ClearanceDeniedError if denied
        self.client.request_clearance(request)


class LedgixTool(BaseTool):
    """Wraps an existing LangChain tool with Vault clearance enforcement.

    Usage::

        from langchain_community.tools import SomeTool
        from ledgix_python.adapters.langchain import LedgixTool

        guarded_tool = LedgixTool.wrap(client, SomeTool(), policy_id="refund-policy")
    """

    name: str = ""
    description: str = ""
    _inner_tool: BaseTool
    _client: LedgixClient
    _policy_id: str | None

    class Config:
        arbitrary_types_allowed = True
        underscore_attrs_are_private = True

    def __init__(
        self,
        inner_tool: BaseTool,
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
        tool: BaseTool,
        *,
        policy_id: str | None = None,
    ) -> LedgixTool:
        """Convenience factory to wrap a tool."""
        return cls(inner_tool=tool, client=client, policy_id=policy_id)

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        ctx: dict[str, Any] = {}
        if self._policy_id:
            ctx["policy_id"] = self._policy_id

        request = ClearanceRequest(
            tool_name=self._inner_tool.name,
            tool_args=kwargs or ({"input": args[0]} if args else {}),
            agent_id=self._client.config.agent_id,
            session_id=self._client.config.session_id,
            context=ctx,
        )

        try:
            self._client.request_clearance(request)
        except ClearanceDeniedError as exc:
            raise ToolException(f"Vault denied: {exc.reason}") from exc

        return self._inner_tool._run(*args, **kwargs)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        ctx: dict[str, Any] = {}
        if self._policy_id:
            ctx["policy_id"] = self._policy_id

        request = ClearanceRequest(
            tool_name=self._inner_tool.name,
            tool_args=kwargs or ({"input": args[0]} if args else {}),
            agent_id=self._client.config.agent_id,
            session_id=self._client.config.session_id,
            context=ctx,
        )

        try:
            await self._client.arequest_clearance(request)
        except ClearanceDeniedError as exc:
            raise ToolException(f"Vault denied: {exc.reason}") from exc

        return await self._inner_tool._arun(*args, **kwargs)
