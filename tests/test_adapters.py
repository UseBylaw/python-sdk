# Bylaw ALCV — Adapter Tests
# Tests for LangChain, LlamaIndex, and CrewAI adapters
# These tests mock the framework imports to avoid needing the actual packages

from __future__ import annotations

import json
import sys
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest
import respx
from httpx import Response

from bylaw_python import BylawClient
from bylaw_python.exceptions import ClearanceDeniedError


# ──────────────────────────────────────────────────────────────────────
# LangChain adapter tests
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def mock_langchain():
    """Mock langchain_core so the adapter can import."""
    mock_core = ModuleType("langchain_core")
    mock_callbacks = ModuleType("langchain_core.callbacks")
    mock_tools = ModuleType("langchain_core.tools")

    # Mock BaseCallbackHandler
    class MockBaseCallbackHandler:
        pass

    mock_callbacks.BaseCallbackHandler = MockBaseCallbackHandler

    # Mock BaseTool
    class MockBaseTool:
        name: str = "test_tool"
        description: str = "A test tool"

        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

        def _run(self, *args, **kwargs):
            return "tool result"

        async def _arun(self, *args, **kwargs):
            return "async tool result"

    mock_tools.BaseTool = MockBaseTool
    mock_tools.ToolException = Exception

    sys.modules["langchain_core"] = mock_core
    sys.modules["langchain_core.callbacks"] = mock_callbacks
    sys.modules["langchain_core.tools"] = mock_tools

    yield MockBaseTool

    # Cleanup
    for mod in ["langchain_core", "langchain_core.callbacks", "langchain_core.tools"]:
        sys.modules.pop(mod, None)
    # Clear cached import in the adapter module
    if "bylaw_python.adapters.langchain" in sys.modules:
        del sys.modules["bylaw_python.adapters.langchain"]


class TestLangChainCallbackHandler:
    @respx.mock
    def test_on_tool_start_approved(
        self, mock_langchain, client: BylawClient, approved_response: dict
    ):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )

        from bylaw_python.adapters.langchain import BylawCallbackHandler

        handler = BylawCallbackHandler(client)
        # Should not raise
        handler.on_tool_start(
            serialized={"name": "test_tool"},
            input_str="test input",
        )

    @respx.mock
    def test_on_tool_start_denied(
        self, mock_langchain, client: BylawClient, denied_response: dict
    ):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=denied_response)
        )

        from bylaw_python.adapters.langchain import BylawCallbackHandler

        handler = BylawCallbackHandler(client, policy_id="test-policy")

        with pytest.raises(ClearanceDeniedError):
            handler.on_tool_start(
                serialized={"name": "test_tool"},
                input_str="test input",
            )


class TestLangChainToolWrapper:
    @respx.mock
    def test_wrap_tool(self, mock_langchain, client: BylawClient, approved_response: dict):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )

        MockBaseTool = mock_langchain

        from bylaw_python.adapters.langchain import BylawTool

        inner = MockBaseTool()
        inner.name = "search"
        inner.description = "Search tool"
        wrapped = BylawTool.wrap(client, inner, policy_id="search-policy")

        assert wrapped.name == "bylaw_search"


# ──────────────────────────────────────────────────────────────────────
# LlamaIndex adapter tests
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def mock_llamaindex():
    """Mock llama_index.core so the adapter can import."""
    mock_core = ModuleType("llama_index")
    mock_core_core = ModuleType("llama_index.core")
    mock_tools = ModuleType("llama_index.core.tools")

    class MockToolMetadata:
        def __init__(self, name="", description=""):
            self.name = name
            self.description = description

    class MockFunctionTool:
        def __init__(self, fn=None, name="", description=""):
            self.metadata = MockToolMetadata(name=name, description=description)
            self._fn = fn

        @classmethod
        def from_defaults(cls, fn=None, name="", description=""):
            return cls(fn=fn, name=name, description=description)

        def call(self, **kwargs):
            if self._fn:
                return self._fn(**kwargs)
            return "tool result"

    class MockToolOutput:
        pass

    mock_tools.FunctionTool = MockFunctionTool
    mock_tools.ToolMetadata = MockToolMetadata
    mock_tools.ToolOutput = MockToolOutput

    sys.modules["llama_index"] = mock_core
    sys.modules["llama_index.core"] = mock_core_core
    sys.modules["llama_index.core.tools"] = mock_tools

    yield MockFunctionTool

    for mod in ["llama_index", "llama_index.core", "llama_index.core.tools"]:
        sys.modules.pop(mod, None)
    if "bylaw_python.adapters.llamaindex" in sys.modules:
        del sys.modules["bylaw_python.adapters.llamaindex"]


class TestLlamaIndexAdapter:
    @respx.mock
    def test_wrap_tool(self, mock_llamaindex, client: BylawClient, approved_response: dict):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )

        MockFunctionTool = mock_llamaindex
        from bylaw_python.adapters.llamaindex import wrap_tool

        def my_search(query: str) -> str:
            return f"results for {query}"

        original = MockFunctionTool(fn=my_search, name="search", description="A search tool")
        guarded = wrap_tool(client, original, policy_id="search-policy")

        assert guarded.metadata.name == "bylaw_search"


# ──────────────────────────────────────────────────────────────────────
# CrewAI adapter tests
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def mock_crewai():
    """Mock crewai so the adapter can import."""
    mock_crew = ModuleType("crewai")
    mock_tools = ModuleType("crewai.tools")

    class MockCrewAIBaseTool:
        name: str = ""
        description: str = ""

        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

        def _run(self, **kwargs):
            return "crew result"

    mock_tools.BaseTool = MockCrewAIBaseTool

    sys.modules["crewai"] = mock_crew
    sys.modules["crewai.tools"] = mock_tools

    yield MockCrewAIBaseTool

    for mod in ["crewai", "crewai.tools"]:
        sys.modules.pop(mod, None)
    if "bylaw_python.adapters.crewai" in sys.modules:
        del sys.modules["bylaw_python.adapters.crewai"]


class TestCrewAIAdapter:
    @respx.mock
    def test_wrap_tool(self, mock_crewai, client: BylawClient, approved_response: dict):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )

        MockBaseTool = mock_crewai
        from bylaw_python.adapters.crewai import BylawCrewAITool

        inner = MockBaseTool(name="search", description="Search tool")
        wrapped = BylawCrewAITool.wrap(client, inner, policy_id="p1")

        assert wrapped.name == "bylaw_search"

    @respx.mock
    def test_denied_returns_blocked_message(
        self, mock_crewai, client: BylawClient, denied_response: dict
    ):
        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=denied_response)
        )

        MockBaseTool = mock_crewai
        from bylaw_python.adapters.crewai import BylawCrewAITool

        inner = MockBaseTool(name="refund", description="Refund tool")
        wrapped = BylawCrewAITool.wrap(client, inner)

        result = wrapped._run(amount=5000)
        assert "BLOCKED" in result
