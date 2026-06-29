# Bylaw ALCV — Manifest and Auto-Instrumentation Tests

from __future__ import annotations

import builtins
import importlib
import json
import sys
import types
from pathlib import Path

import pytest
import respx
from httpx import Response

import bylaw_python as bylaw
from bylaw_python.manifest import load_manifest


def _make_module(name: str, source: str) -> types.ModuleType:
    module = types.ModuleType(name)
    sys.modules[name] = module
    exec(source, module.__dict__)
    return module


class TestManifestLoading:
    def test_load_manifest_from_inline_dict(self):
        manifest = load_manifest(
            {"enforce": [{"tool": "stripe_*", "policy_id": "financial-high-risk"}]}
        )

        assert manifest.match("stripe_charge") is not None
        assert manifest.match("stripe_charge").policy_id == "financial-high-risk"

    def test_load_manifest_from_discovered_json(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        path = tmp_path / "bylaw.json"
        path.write_text(
            json.dumps({"enforce": [{"tool": "db_write*", "policy_id": "data-mutation"}]}),
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)

        manifest = load_manifest()

        assert manifest.source == str(path)
        assert manifest.match("db_write_user").policy_id == "data-mutation"

    def test_load_manifest_from_yaml(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        path = tmp_path / "bylaw.yaml"
        path.write_text(
            "enforce:\n"
            "  - tool: \"stripe_*\"\n"
            "    policy_id: \"financial-high-risk\"\n",
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)

        manifest = load_manifest()

        assert manifest.source == str(path)
        assert manifest.match("stripe_refund").policy_id == "financial-high-risk"

    def test_missing_pyyaml_error_is_helpful(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        path = tmp_path / "bylaw.yaml"
        path.write_text("enforce: []\n", encoding="utf-8")

        real_import = builtins.__import__

        def fake_import(name: str, *args, **kwargs):
            if name == "yaml":
                raise ImportError("No module named yaml")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)

        with pytest.raises(ImportError, match="PyYAML is required"):
            load_manifest(path)


class TestAutoInstrument:
    @respx.mock
    def test_wraps_only_public_functions_defined_in_module(
        self,
        monkeypatch: pytest.MonkeyPatch,
        vault_config,
        approved_response: dict,
    ):
        route = respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )
        bylaw.configure(vault_config)

        external_module = _make_module(
            "external_tools",
            "def imported_fn(value):\n"
            "    return value\n",
        )
        tools_module = _make_module(
            "test_tools_module",
            "import bylaw_python as bylaw\n"
            "def stripe_charge(amount):\n"
            "    return bylaw.current_token()\n"
            "def _hidden_tool():\n"
            "    return 'hidden'\n",
        )
        tools_module.imported_fn = external_module.imported_fn
        original_imported = tools_module.imported_fn

        wrapped = bylaw.auto_instrument(
            tools_module,
            manifest={"enforce": [{"tool": "stripe_*", "policy_id": "financial-high-risk"}]},
        )

        assert wrapped == ["test_tools_module.stripe_charge"]
        assert tools_module.imported_fn is original_imported
        assert tools_module.stripe_charge(45) == approved_response["token"]

        body = json.loads(route.calls[0].request.content)
        assert body["context"]["policy_id"] == "financial-high-risk"
        assert body["tool_name"] == "stripe_charge"

    @respx.mock
    def test_manifest_context_gdpr_fields_reach_wire(
        self,
        vault_config,
        approved_response: dict,
    ):
        route = respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )
        bylaw.configure(vault_config)
        tools_module = _make_module(
            "test_gdpr_tools_module",
            "import bylaw_python as bylaw\n"
            "def customer_export():\n"
            "    return bylaw.current_token()\n",
        )

        bylaw.auto_instrument(
            tools_module,
            manifest={
                "enforce": [
                    {
                        "tool": "customer_export",
                        "context": {
                            "purpose": "billing",
                            "data_categories": ["customer_email"],
                            "dataset_ref": "prod_customer_support_kb",
                        },
                    }
                ]
            },
        )

        assert tools_module.customer_export() == approved_response["token"]
        body = json.loads(route.calls[0].request.content)
        assert body["context"]["purpose"] == "billing"
        assert body["context"]["data_categories"] == ["customer_email"]
        assert body["context"]["dataset_ref"] == "prod_customer_support_kb"

    @respx.mock
    def test_recurse_instruments_submodules(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        vault_config,
        approved_response: dict,
    ):
        package_dir = tmp_path / "demo_pkg"
        package_dir.mkdir()
        (package_dir / "__init__.py").write_text("", encoding="utf-8")
        (package_dir / "tools.py").write_text(
            "import bylaw_python as bylaw\n"
            "def stripe_refund(amount):\n"
            "    return bylaw.current_token()\n",
            encoding="utf-8",
        )
        monkeypatch.syspath_prepend(str(tmp_path))

        package = importlib.import_module("demo_pkg")
        submodule = importlib.import_module("demo_pkg.tools")

        respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )
        bylaw.configure(vault_config)

        wrapped = bylaw.auto_instrument(
            package,
            manifest={"enforce": [{"tool": "stripe_*", "policy_id": "financial-high-risk"}]},
            recurse=True,
        )

        assert "demo_pkg.tools.stripe_refund" in wrapped
        assert submodule.stripe_refund(12) == approved_response["token"]


class TestToolDecorator:
    @respx.mock
    def test_tool_uses_loaded_manifest_rule(
        self,
        vault_config,
        approved_response: dict,
    ):
        route = respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )
        bylaw.configure(vault_config)
        module = _make_module("empty_tools_module", "")
        bylaw.auto_instrument(
            module,
            manifest={"enforce": [{"tool": "special_*", "policy_id": "manifest-policy"}]},
        )

        @bylaw.tool
        def special_refund():
            return bylaw.current_token()

        assert special_refund() == approved_response["token"]
        body = json.loads(route.calls[0].request.content)
        assert body["context"]["policy_id"] == "manifest-policy"

    @respx.mock
    def test_tool_explicit_override_wins(
        self,
        vault_config,
        approved_response: dict,
    ):
        route = respx.post("https://vault.test/request-clearance").mock(
            return_value=Response(200, json=approved_response)
        )
        bylaw.configure(vault_config)
        module = _make_module("override_tools_module", "")
        bylaw.auto_instrument(
            module,
            manifest={
                "enforce": [
                    {
                        "tool": "special_*",
                        "policy_id": "manifest-policy",
                        "context": {"source": "manifest"},
                    }
                ]
            },
        )

        @bylaw.tool(policy_id="override-policy", context={"source": "override"})
        def special_charge():
            return bylaw.current_token()

        assert special_charge() == approved_response["token"]
        body = json.loads(route.calls[0].request.content)
        assert body["context"] == {
            "source": "override",
            "policy_id": "override-policy",
        }
