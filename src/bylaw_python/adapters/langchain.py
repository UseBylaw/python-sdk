# Bylaw ALCV — LangChain Adapter
# Provides a callback handler and tool wrapper for LangChain integration

from __future__ import annotations

from typing import Any

from ..client import BylawClient
from ..exceptions import ClearanceDeniedError
from ._core import build_clearance_request, resolve_client

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.tools import BaseTool, ToolException
except ImportError as exc:
    raise ImportError(
        "LangChain adapter requires langchain-core. "
        "Install with: pip install bylaw-python[langchain]"
    ) from exc


class BylawCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that intercepts tool calls for Vault clearance.

    Usage::

        from bylaw_python.adapters.langchain import BylawCallbackHandler

        handler = BylawCallbackHandler(client)
        agent = create_agent(callbacks=[handler])

    If :func:`bylaw_python.configure` has been called, *client* may be omitted::

        handler = BylawCallbackHandler()
    """

    def __init__(self, client: BylawClient | None = None, *, policy_id: str | None = None) -> None:
        self._client = client
        self.policy_id = policy_id

    @property
    def client(self) -> BylawClient:
        return resolve_client(self._client)

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

        extra_context = {"langchain_metadata": metadata} if metadata else None
        request = build_clearance_request(
            tool_name=tool_name,
            tool_args=tool_args,
            client=self.client,
            policy_id=self.policy_id,
            extra_context=extra_context,
        )

        # This will raise ClearanceDeniedError if denied
        self.client.request_clearance(request)


class BylawTool(BaseTool):
    """Wraps an existing LangChain tool with Vault clearance enforcement.

    Usage with explicit client::

        from langchain_community.tools import SomeTool
        from bylaw_python.adapters.langchain import BylawTool

        guarded_tool = BylawTool.wrap(client, SomeTool(), policy_id="refund-policy")

    Usage after :func:`bylaw_python.configure`::

        guarded_tool = BylawTool.wrap(SomeTool(), policy_id="refund-policy")
    """

    name: str = ""
    description: str = ""
    _inner_tool: BaseTool
    _client: BylawClient | None
    _policy_id: str | None

    class Config:
        arbitrary_types_allowed = True
        underscore_attrs_are_private = True

    def __init__(
        self,
        inner_tool: BaseTool,
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
        client_or_tool: BylawClient | BaseTool,
        tool: BaseTool | None = None,
        *,
        policy_id: str | None = None,
    ) -> BylawTool:
        """Convenience factory to wrap a tool.

        Supports two call signatures:

        - ``BylawTool.wrap(client, tool, policy_id=...)`` — explicit client
        - ``BylawTool.wrap(tool, policy_id=...)`` — uses global client from :func:`bylaw_python.configure`
        """
        if isinstance(client_or_tool, BylawClient):
            return cls(inner_tool=tool, client=client_or_tool, policy_id=policy_id)  # type: ignore[arg-type]
        # client_or_tool is actually the tool; no explicit client
        return cls(inner_tool=client_or_tool, client=None, policy_id=policy_id)

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        client = self._resolve_client()
        request = build_clearance_request(
            tool_name=self._inner_tool.name,
            tool_args=kwargs or ({"input": args[0]} if args else {}),
            client=client,
            policy_id=self._policy_id,
        )

        try:
            client.request_clearance(request)
        except ClearanceDeniedError as exc:
            raise ToolException(f"Vault denied: {exc.reason}") from exc

        return self._inner_tool._run(*args, **kwargs)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        client = self._resolve_client()
        request = build_clearance_request(
            tool_name=self._inner_tool.name,
            tool_args=kwargs or ({"input": args[0]} if args else {}),
            client=client,
            policy_id=self._policy_id,
        )

        try:
            await client.arequest_clearance(request)
        except ClearanceDeniedError as exc:
            raise ToolException(f"Vault denied: {exc.reason}") from exc

        return await self._inner_tool._arun(*args, **kwargs)
