"""Bylaw CLI — local dev quickstart and management commands."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import click

COMPOSE_FILE = "docker-compose.bylaw.yml"
ENV_FILE = ".env.bylaw"
MANIFEST_FILE = "bylaw.yaml"

VAULT_PORT = 8080
JUDGE_PORT = 8000
POSTGRES_PORT = 5433
DEV_API_KEY = "ldgx-dev-key-00000000"
DEV_AGENT_ID = "my-agent"
DEV_TENANT = "dev-tenant"

COMPOSE_TEMPLATE = textwrap.dedent("""\
    services:
      postgres:
        image: pgvector/pgvector:pg16
        container_name: bylaw_dev_postgres
        restart: unless-stopped
        ports:
          - "127.0.0.1:{postgres_port}:5432"
        environment:
          POSTGRES_USER: bylaw
          POSTGRES_PASSWORD: bylaw-dev
          POSTGRES_DB: bylaw_dev
        volumes:
          - bylaw_pgdata:/var/lib/postgresql/data
        healthcheck:
          test: ["CMD-SHELL", "pg_isready -U bylaw"]
          interval: 5s
          timeout: 3s
          retries: 10

      vault:
        image: ghcr.io/bylaw-dev/alcv-vault:latest
        container_name: bylaw_dev_vault
        restart: unless-stopped
        ports:
          - "127.0.0.1:{vault_port}:8000"
        environment:
          VAULT_PORT: "8000"
          VAULT_JUDGE_URL: http://bylaw_dev_judge:8000
          VAULT_JWT_ISSUER: alcv-vault
          VAULT_JWT_AUDIENCE: ledgix-sdk
          VAULT_JWT_TTL: "300"
          VAULT_KEY_ID: dev-key-001
          VAULT_ALLOW_INSECURE_DEV_MODE: "true"
          VAULT_DEV_TENANT_ID: {tenant_id}
          VAULT_DEV_API_KEY: {api_key}
          VAULT_DEV_DB_URL: postgres://bylaw:bylaw-dev@bylaw_dev_postgres:5432/bylaw_dev?sslmode=disable
          VAULT_RATE_LIMIT_RPS: "0"
        depends_on:
          postgres:
            condition: service_healthy
        networks:
          - bylaw_dev_net

      judge:
        image: ghcr.io/bylaw-dev/llm-judge:latest
        container_name: bylaw_dev_judge
        restart: unless-stopped
        environment:
          DATABASE_URL: postgres://bylaw:bylaw-dev@bylaw_dev_postgres:5432/bylaw_dev?sslmode=disable
          EMBEDDING_MODEL: bedrock/amazon.titan-embed-text-v2:0
          EVAL_MODEL: bedrock/amazon.nova-pro-v1:0
          AWS_REGION: us-east-1
          LOG_FORMAT: json
        depends_on:
          postgres:
            condition: service_healthy
        networks:
          - bylaw_dev_net
        healthcheck:
          test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
          interval: 10s
          timeout: 3s
          retries: 5
          start_period: 10s

    volumes:
      bylaw_pgdata:

    networks:
      bylaw_dev_net:
        driver: bridge
""")

MANIFEST_TEMPLATE = textwrap.dedent("""\
    # Bylaw manifest — maps tool names to policy IDs.
    # See https://docs.bylaw.dev/sdk/manifest for full syntax.
    version: "1"
    defaults:
      review_mode: block

    tools:
      # Example: uncomment and adjust for your tools
      # stripe_refund:
      #   policy_id: refund-policy
      #   confidence_floor: high
      # send_email:
      #   policy_id: comms-policy
""")


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _compose_cmd() -> list[str]:
    result = subprocess.run(
        ["docker", "compose", "version"],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        return ["docker", "compose"]
    result2 = subprocess.run(
        ["docker-compose", "version"],
        capture_output=True, text=True,
    )
    if result2.returncode == 0:
        return ["docker-compose"]
    return []


def _compose_base() -> list[str]:
    cmd = _compose_cmd()
    if not cmd:
        click.echo("Error: docker compose is not available.", err=True)
        sys.exit(1)
    return [*cmd, "-f", COMPOSE_FILE, "-p", "bylaw-dev"]


def _poll_health(url: str, timeout: int = 90) -> bool:
    """Poll a health endpoint until it returns 200 or timeout."""
    import urllib.request
    import urllib.error

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, OSError, TimeoutError):
            pass
        time.sleep(2)
    return False


@click.group()
@click.version_option(package_name="bylaw-python")
def main():
    """Bylaw CLI — local development tools for the ALCV platform."""
    pass


@main.command()
@click.option("--vault-port", default=VAULT_PORT, type=int, help="Host port for vault")
@click.option("--api-key", default=DEV_API_KEY, help="Dev API key")
@click.option("--tenant-id", default=DEV_TENANT, help="Dev tenant ID")
@click.option("--skip-health-check", is_flag=True, help="Don't wait for services to become healthy")
def init(vault_port: int, api_key: str, tenant_id: str, skip_health_check: bool):
    """Scaffold and start a local Bylaw dev environment.

    Creates docker-compose, env, and manifest files, then starts all
    services. On a clean machine with Docker, first clearance request
    should succeed within 60 seconds.
    """
    if not _docker_available():
        click.echo("Error: Docker is not installed or not in PATH.", err=True)
        click.echo("Install Docker Desktop: https://docs.docker.com/get-docker/", err=True)
        sys.exit(1)

    compose_cmd = _compose_cmd()
    if not compose_cmd:
        click.echo("Error: Neither 'docker compose' nor 'docker-compose' found.", err=True)
        sys.exit(1)

    cwd = Path.cwd()

    compose_path = cwd / COMPOSE_FILE
    if compose_path.exists():
        click.echo(f"  {COMPOSE_FILE} already exists, skipping.")
    else:
        compose_content = COMPOSE_TEMPLATE.format(
            vault_port=vault_port,
            postgres_port=POSTGRES_PORT,
            api_key=api_key,
            tenant_id=tenant_id,
        )
        compose_path.write_text(compose_content)
        click.echo(f"  Created {COMPOSE_FILE}")

    env_path = cwd / ENV_FILE
    if env_path.exists():
        click.echo(f"  {ENV_FILE} already exists, skipping.")
    else:
        env_content = "\n".join([
            f"BYLAW_VAULT_URL=http://localhost:{vault_port}",
            f"BYLAW_VAULT_API_KEY={api_key}",
            f"BYLAW_AGENT_ID={DEV_AGENT_ID}",
            "",
        ])
        env_path.write_text(env_content)
        click.echo(f"  Created {ENV_FILE}")

    manifest_path = cwd / MANIFEST_FILE
    if manifest_path.exists():
        click.echo(f"  {MANIFEST_FILE} already exists, skipping.")
    else:
        manifest_path.write_text(MANIFEST_TEMPLATE)
        click.echo(f"  Created {MANIFEST_FILE}")

    click.echo("\nStarting services...")
    base = _compose_base()
    result = subprocess.run([*base, "up", "-d", "--pull", "always"], capture_output=True, text=True)
    if result.returncode != 0:
        click.echo(f"Error starting services:\n{result.stderr}", err=True)
        sys.exit(1)
    click.echo("  Containers started.")

    if not skip_health_check:
        click.echo("\nWaiting for services to become healthy...")
        vault_url = f"http://localhost:{vault_port}/health"
        if _poll_health(vault_url, timeout=90):
            click.echo("  Vault is healthy.")
        else:
            click.echo(
                f"  Warning: Vault did not respond at {vault_url} within 90s.\n"
                "  Run 'bylaw status' to check, or 'docker compose -f docker-compose.bylaw.yml logs' for details.",
                err=True,
            )

    click.echo("\n" + "=" * 56)
    click.echo("  Bylaw dev environment is ready!")
    click.echo("=" * 56)
    click.echo(f"""
  Vault:     http://localhost:{vault_port}
  API Key:   {api_key}
  Tenant:    {tenant_id}

  Next steps:

    1. Add to your agent:

       import bylaw_python as bylaw
       bylaw.configure(
           vault_url="http://localhost:{vault_port}",
           vault_api_key="{api_key}",
           agent_id="{DEV_AGENT_ID}",
       )
       bylaw.auto_instrument(tools)

    2. Or source the env file and configure() picks it up:

       source {ENV_FILE}   # or: set -a; . {ENV_FILE}; set +a
       bylaw.configure()

    3. Upload a policy:

       curl -X POST http://localhost:{vault_port}/admin/upload-policy \\
         -H "X-Vault-API-Key: {api_key}" \\
         -F "file=@your-policy.md" \\
         -F "documentName=My Policy" \\
         -F "policyId=my-policy"
""")


@main.command()
def status():
    """Check whether the local Bylaw dev environment is running."""
    if not (Path.cwd() / COMPOSE_FILE).exists():
        click.echo(f"No {COMPOSE_FILE} found in current directory.")
        click.echo("Run 'bylaw init' to create a local dev environment.")
        return

    base = _compose_base()
    result = subprocess.run([*base, "ps", "--format", "json"], capture_output=True, text=True)
    if result.returncode != 0:
        click.echo("Could not query container status.")
        click.echo(result.stderr)
        return

    containers: list[dict] = []
    raw = result.stdout.strip()
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                containers = parsed
            elif isinstance(parsed, dict):
                containers = [parsed]
        except json.JSONDecodeError:
            for line in raw.splitlines():
                line = line.strip()
                if line:
                    try:
                        containers.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

    if not containers:
        click.echo("No containers running. Run 'bylaw init' to start.")
        return

    click.echo(f"{'Service':<20} {'State':<12} {'Health':<12} {'Ports'}")
    click.echo("-" * 70)
    for c in containers:
        name = c.get("Service") or c.get("Name", "?")
        state = c.get("State", "?")
        health = c.get("Health", "-")
        ports = c.get("Publishers") or c.get("Ports", "")
        if isinstance(ports, list):
            port_strs = []
            for p in ports:
                if isinstance(p, dict) and p.get("PublishedPort"):
                    port_strs.append(f":{p['PublishedPort']}")
            ports = ", ".join(port_strs) if port_strs else "-"
        click.echo(f"{name:<20} {state:<12} {health:<12} {ports}")

    env_path = Path.cwd() / ENV_FILE
    if env_path.exists():
        click.echo(f"\nEnv file: {env_path}")


@main.command()
@click.option("--volumes", is_flag=True, help="Also remove data volumes")
@click.confirmation_option(prompt="This will stop and remove all Bylaw dev containers. Continue?")
def teardown(volumes: bool):
    """Stop and remove the local Bylaw dev environment."""
    compose_path = Path.cwd() / COMPOSE_FILE
    if not compose_path.exists():
        click.echo(f"No {COMPOSE_FILE} found in current directory. Nothing to tear down.")
        return

    base = _compose_base()
    cmd = [*base, "down"]
    if volumes:
        cmd.append("-v")

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        click.echo(f"Error during teardown:\n{result.stderr}", err=True)
        sys.exit(1)

    click.echo("Bylaw dev environment stopped and removed.")
    if volumes:
        click.echo("Data volumes removed.")


if __name__ == "__main__":
    main()
