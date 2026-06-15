# Ledgix ALCV — LlamaIndex Adapter
# Wraps LlamaIndex tools with Vault clearance enforcement

from __future__ import annotations

from typing import Any

from ..client import LedgixClient
from ._core import build_clearance_request, resolve_client

try:
    from llama_index.core.tools import FunctionTool, ToolMetadata, ToolOutput
except ImportError as exc:
    raise ImportError(
        "LlamaIndex adapter requires llama-index-core. "
        "Install with: pip install ledgix-python[llamaindex]"
    ) from exc


class LedgixToolWrapper:
    """Wraps a LlamaIndex tool with Vault clearance enforcement.

    Usage with explicit client::

        from llama_index.core.tools import FunctionTool
        from ledgix_python.adapters.llamaindex import LedgixToolWrapper

        tool = FunctionTool.from_defaults(fn=my_tool, name="search")
        guarded = LedgixToolWrapper(client, tool)

    Usage after :func:`ledgix_python.configure`::

        guarded = LedgixToolWrapper(tool=tool)
    """

    def __init__(
        self,
        client: LedgixClient | None = None,
        tool: FunctionTool | None = None,
        *,
        policy_id: str | None = None,
    ) -> None:
        self._client = client
        self._inner_tool = tool
        self._policy_id = policy_id

        # Create the wrapped tool
        self.tool = FunctionTool.from_defaults(
            fn=self._guarded_call,
            name=f"ledgix_{tool.metadata.name}",  # type: ignore[union-attr]
            description=tool.metadata.description or "",  # type: ignore[union-attr]
        )

    def _resolve_client(self) -> LedgixClient:
        return resolve_client(self._client)

    def _guarded_call(self, **kwargs: Any) -> Any:
        """Wrapper that requests clearance before calling the inner tool."""
        client = self._resolve_client()
        request = build_clearance_request(
            tool_name=self._inner_tool.metadata.name,  # type: ignore[union-attr]
            tool_args=kwargs,
            client=client,
            policy_id=self._policy_id,
        )

        client.request_clearance(request)
        return self._inner_tool.call(**kwargs)  # type: ignore[union-attr]


def wrap_tool(
    client_or_tool: LedgixClient | FunctionTool,
    tool: FunctionTool | None = None,
    *,
    policy_id: str | None = None,
) -> FunctionTool:
    """Wrap a LlamaIndex tool with Vault clearance enforcement.

    Returns the guarded FunctionTool ready for use in an agent.

    Supports two call signatures:

    - ``wrap_tool(client, tool, policy_id=...)`` — explicit client
    - ``wrap_tool(tool, policy_id=...)`` — uses global client from :func:`ledgix_python.configure`
    """
    if isinstance(client_or_tool, LedgixClient):
        wrapper = LedgixToolWrapper(client_or_tool, tool, policy_id=policy_id)
    else:
        wrapper = LedgixToolWrapper(None, client_or_tool, policy_id=policy_id)
    return wrapper.tool
