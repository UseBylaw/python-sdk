# Ledgix ALCV — LlamaIndex Adapter
# Wraps LlamaIndex tools with Vault clearance enforcement

from __future__ import annotations

from typing import Any

from ..client import LedgixClient
from ..exceptions import ClearanceDeniedError
from ..models import ClearanceRequest

try:
    from llama_index.core.tools import FunctionTool, ToolMetadata, ToolOutput
except ImportError as exc:
    raise ImportError(
        "LlamaIndex adapter requires llama-index-core. "
        "Install with: pip install ledgix-python[llamaindex]"
    ) from exc


class LedgixToolWrapper:
    """Wraps a LlamaIndex tool with Vault clearance enforcement.

    Usage::

        from llama_index.core.tools import FunctionTool
        from ledgix_python.adapters.llamaindex import LedgixToolWrapper

        def my_tool(query: str) -> str:
            return f"Result for {query}"

        tool = FunctionTool.from_defaults(fn=my_tool, name="search")
        guarded = LedgixToolWrapper(client, tool)

        # Use guarded.tool in your LlamaIndex agent
    """

    def __init__(
        self,
        client: LedgixClient,
        tool: FunctionTool,
        *,
        policy_id: str | None = None,
    ) -> None:
        self._client = client
        self._inner_tool = tool
        self._policy_id = policy_id

        # Create the wrapped tool
        self.tool = FunctionTool.from_defaults(
            fn=self._guarded_call,
            name=f"ledgix_{tool.metadata.name}",
            description=tool.metadata.description or "",
        )

    def _guarded_call(self, **kwargs: Any) -> Any:
        """Wrapper that requests clearance before calling the inner tool."""
        ctx: dict[str, Any] = {}
        if self._policy_id:
            ctx["policy_id"] = self._policy_id

        request = ClearanceRequest(
            tool_name=self._inner_tool.metadata.name,
            tool_args=kwargs,
            agent_id=self._client.config.agent_id,
            session_id=self._client.config.session_id,
            context=ctx,
        )

        self._client.request_clearance(request)
        return self._inner_tool.call(**kwargs)


def wrap_tool(
    client: LedgixClient,
    tool: FunctionTool,
    *,
    policy_id: str | None = None,
) -> FunctionTool:
    """Convenience function to wrap a LlamaIndex tool.

    Returns the guarded FunctionTool ready for use in an agent.
    """
    wrapper = LedgixToolWrapper(client, tool, policy_id=policy_id)
    return wrapper.tool
