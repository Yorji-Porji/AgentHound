"""Local collector.

Scans the current machine for installed AI assistants, their configured MCP
servers, and the non-human identities the runtime can pick up from disk.
Produces Agent, AgentRuntime, MCPServer, MCPTool, NHI, and Developer nodes
plus the permission edges that wire them together.

Design rules:

- **Never read or store credential values.** Only presence and metadata
  (provider, profile name, public-key filename, host). The tool's job is to
  map the graph, not exfiltrate secrets.
- **Fail soft.** Every file open, JSON parse, and YAML parse is wrapped — a
  missing or malformed config produces a warning, not a crash.
- **Cross-platform paths.** macOS, Linux, and Windows config locations are
  all enumerated. Each agent runtime is tagged with its OS family.
"""

from __future__ import annotations

import getpass
import json
import os
import platform
import socket
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from agenthound.collectors.base import CollectionResult, Collector

if TYPE_CHECKING:
    from agenthound.audit import AuditLog
    from agenthound.scope import ScopeGuard
from agenthound.schema.edges import Edge, PermissionEdgeKind
from agenthound.schema.nodes import (
    Node,
    agent_node,
    developer_node,
    mcp_server_node,
    mcp_tool_node,
    nhi_node,
    runtime_node,
)

# --- Known MCP server registry ------------------------------------------------
#
# Loaded from `agenthound/data/known_mcp_servers.yaml`. Override or extend
# with `LocalCollector(known_servers=path)` or `--known-servers` on the CLI.

_REGISTRY_PATH = Path(__file__).parent.parent / "data" / "known_mcp_servers.yaml"


def _load_registry(path: Path | None = None) -> dict[str, dict[str, Any]]:
    """Load the known-MCP-server registry from YAML."""
    target = path or _REGISTRY_PATH
    try:
        data = yaml.safe_load(target.read_text())
    except (OSError, yaml.YAMLError):
        return {}
    if not isinstance(data, dict):
        return {}
    return data.get("servers") or {}


# --- Agent install fingerprints -----------------------------------------------

def _agent_install_paths(home: Path) -> dict[str, list[Path]]:
    """Per-OS install path candidates for each known agent kind."""
    return {
        "cursor": [
            home / ".cursor",
            home / "Library" / "Application Support" / "Cursor",
            home / "AppData" / "Roaming" / "Cursor",
        ],
        "claude_desktop": [
            home / "Library" / "Application Support" / "Claude",
            home / ".config" / "Claude",
            home / "AppData" / "Roaming" / "Claude",
        ],
        "claude_code": [
            home / ".claude",
            home / ".config" / "anthropic" / "claude-code",
            home / "AppData" / "Roaming" / "anthropic" / "claude-code",
        ],
        "vscode": [
            home / ".vscode",
            home / "Library" / "Application Support" / "Code",
            home / "AppData" / "Roaming" / "Code",
        ],
        "zed": [
            home / ".config" / "zed",
            home / "Library" / "Application Support" / "Zed",
        ],
    }


def _first_existing(paths: Iterable[Path]) -> Path | None:
    for p in paths:
        try:
            if p.exists():
                return p
        except OSError:
            continue
    return None


# --- MCP config file locations ------------------------------------------------

def _mcp_config_paths(home: Path) -> list[tuple[str, Path]]:
    """Return (agent_kind, path) for every known MCP config location.

    The `mcpServers` keyed JSON format used by Claude Desktop has been
    adopted by Cursor and Claude Code as well, so the same parser handles
    all three.
    """
    mac = home / "Library" / "Application Support"
    roaming = home / "AppData" / "Roaming"
    return [
        ("claude_desktop", mac / "Claude" / "claude_desktop_config.json"),
        ("claude_desktop", home / ".config" / "Claude" / "claude_desktop_config.json"),
        ("claude_desktop", roaming / "Claude" / "claude_desktop_config.json"),
        ("cursor", home / ".cursor" / "mcp.json"),
        ("cursor", mac / "Cursor" / "User" / "globalStorage" / "mcp.json"),
        ("claude_code", home / ".claude" / "mcp.json"),
        ("vscode", home / ".vscode" / "mcp.json"),
    ]


# --- Credential file parsers --------------------------------------------------
#
# Each parser returns a list of identifiers (profile names, hostnames, public-
# key filenames) — never the credential value.

def _aws_profile_names(path: Path) -> list[str]:
    """Parse AWS credentials/config file for profile names. Values are not read."""
    profiles: list[str] = []
    try:
        text = path.read_text()
    except OSError:
        return profiles
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].strip()
            if name.startswith("profile "):
                name = name[len("profile "):].strip()
            if name:
                profiles.append(name)
    return profiles


def _parse_role_arn(arn: str) -> tuple[str | None, str | None, str | None]:
    """Split an IAM role ARN into ``(account_id, role_name, partition)``.

    ``arn:aws:iam::123456789012:role/path/Name`` -> ``("123456789012", "Name",
    "aws")``. Returns ``None`` fields for anything that is not a role ARN; the
    caller still emits the role NHI keyed on the raw ARN, just without the
    decomposed properties. An ARN is an identifier, never a secret.
    """
    parts = arn.split(":")
    if len(parts) < 6 or parts[0] != "arn" or parts[2] != "iam":
        return None, None, None
    partition = parts[1] or None
    account_id = parts[4] or None
    resource = parts[5]
    if not resource.startswith("role/"):
        return account_id, None, partition
    role_name = resource[len("role/") :].rsplit("/", 1)[-1] or None
    return account_id, role_name, partition


def _aws_assume_roles(path: Path) -> list[dict[str, str]]:
    """Parse ``~/.aws/config`` for assume-role profiles. Values are not secrets.

    Returns one dict per profile that declares a ``role_arn``, carrying the
    non-secret assume-role wiring only: ``profile``, ``role_arn``,
    ``source_profile``, ``mfa_serial``, ``credential_source``. These are
    identifiers and config (an ARN, an MFA *device* serial) — never a credential
    value. This is topology ("X can assume role Y"); what the role is allowed to
    do needs IAM, not this file (see the ``aws-iam`` collector).
    """
    sections: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    try:
        text = path.read_text()
    except OSError:
        return sections
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].strip()
            if name.startswith("profile "):
                name = name[len("profile ") :].strip()
            current = {"profile": name}
            sections.append(current)
            continue
        if current is None or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip().lower(), value.strip()
        if value and key in {"role_arn", "source_profile", "mfa_serial", "credential_source"}:
            current[key] = value
    return [s for s in sections if "role_arn" in s]


def _gh_hosts(path: Path) -> list[str]:
    """Parse gh CLI hosts file for hostnames and usernames. Tokens are not read."""
    out: list[str] = []
    try:
        data = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError):
        return out
    if not isinstance(data, dict):
        return out
    for host, cfg in data.items():
        if isinstance(cfg, dict):
            user = cfg.get("user") or cfg.get("git_protocol")
            out.append(f"{host}:{user}" if user else str(host))
        else:
            out.append(str(host))
    return out


def _ssh_pubkeys(ssh_dir: Path) -> list[str]:
    """Enumerate public SSH key filenames. Private key contents are never read."""
    if not ssh_dir.exists():
        return []
    return sorted(p.name for p in ssh_dir.glob("*.pub"))


def _kube_contexts(path: Path) -> list[str]:
    """Parse kubeconfig for context names. Tokens and client certs are not read."""
    out: list[str] = []
    try:
        data = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError):
        return out
    if not isinstance(data, dict):
        return out
    for ctx in data.get("contexts", []) or []:
        if isinstance(ctx, dict) and "name" in ctx:
            out.append(str(ctx["name"]))
    return out


def _npmrc_registries(path: Path) -> list[str]:
    """Parse .npmrc for registry hosts. Auth tokens are not read."""
    out: list[str] = []
    try:
        text = path.read_text()
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if "registry=" in line and not line.startswith("#"):
            _, _, url = line.partition("registry=")
            out.append(url.strip())
    return out


# --- MCP env-var → provider inference -----------------------------------------
#
# A server's config hands it credentials via environment variables. The var
# *names* (never the values) usually name the provider the server reaches —
# AWS_*, GITHUB_TOKEN, STRIPE_API_KEY, ... For an unknown/custom server this is
# the main signal of its access surface. Unmatched names stay generic.

_ENV_PROVIDER_PATTERNS: dict[str, tuple[str, ...]] = {
    "aws": ("AWS_",),
    "github": ("GITHUB_", "GH_TOKEN"),
    "gitlab": ("GITLAB_",),
    "slack": ("SLACK_",),
    "gcp": ("GOOGLE_", "GCP_", "GCLOUD_"),
    "azure": ("AZURE_",),
    "openai": ("OPENAI_",),
    "anthropic": ("ANTHROPIC_",),
    "salesforce": ("SALESFORCE_", "SF_"),
    "stripe": ("STRIPE_",),
    "notion": ("NOTION_",),
    "linear": ("LINEAR_",),
    "atlassian": ("JIRA_", "CONFLUENCE_", "ATLASSIAN_"),
    "cloudflare": ("CLOUDFLARE_", "CF_API"),
    "postgres": ("POSTGRES_", "PGPASSWORD", "PGUSER", "DATABASE_URL"),
}


def _providers_from_env(env_keys: Iterable[str]) -> dict[str, list[str]]:
    """Map credential env-var *names* to the providers they reach.

    Returns ``{provider: [matching env-var names]}`` — names only, values are
    never read. A name matching no known pattern is omitted, so the caller keeps
    the generic credential edge for it.
    """
    out: dict[str, list[str]] = {}
    for key in env_keys:
        upper = key.upper()
        for provider, patterns in _ENV_PROVIDER_PATTERNS.items():
            if any(upper == p or upper.startswith(p) for p in patterns):
                out.setdefault(provider, []).append(key)
                break
    return out


# ------------------------------------------------------------------------------


class LocalCollector(Collector):
    """Scan the current machine for AI agent infrastructure.

    Parameters
    ----------
    home : optional
        Override the home directory to scan. Defaults to ``Path.home()``.
    hostname : optional
        Override the detected hostname. Useful when the collector output is
        being assembled off-host.
    known_servers : optional
        Path to a YAML registry overlay. Entries here override or extend the
        bundled default.
    """

    def __init__(
        self,
        home: Path | None = None,
        hostname: str | None = None,
        *,
        known_servers: Path | None = None,
        guard: ScopeGuard | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        super().__init__(guard=guard, audit=audit)
        self.home = home or Path.home()
        self.hostname = hostname or socket.gethostname()
        self.os_family = platform.system()
        self.username = getpass.getuser() if hostname is None else "unknown"
        self.registry = _load_registry()
        if known_servers is not None:
            overlay = _load_registry(known_servers)
            self.registry = {**self.registry, **overlay}

    # -- Collection entry point ------------------------------------------------

    def collect(self) -> CollectionResult:
        result = CollectionResult()

        # Developer + runtime are the anchor nodes — every other node hangs off these.
        dev = developer_node(self.username, self.hostname)
        runtime = runtime_node(self.hostname, runtime_kind="workstation", os_name=self.os_family)
        result.nodes.extend([dev, runtime])

        agents_by_kind = self._collect_agents(runtime, dev, result)
        self._collect_mcp_configs(agents_by_kind, runtime, result)
        self._collect_credentials(runtime, result)

        return result

    # -- Agents ----------------------------------------------------------------

    def _collect_agents(
        self,
        runtime: Node,
        dev: Node,
        result: CollectionResult,
    ) -> dict[str, Node]:
        agents: dict[str, Node] = {}
        for kind_detail, candidates in _agent_install_paths(self.home).items():
            install = _first_existing(candidates)
            if install is None:
                continue
            agent = agent_node(
                name=f"{kind_detail}@{self.hostname}",
                kind_detail=kind_detail,
                install_path=str(install),
            )
            agents[kind_detail] = agent
            result.nodes.append(agent)
            result.edges.extend(
                [
                    Edge(PermissionEdgeKind.RUNS_AS, agent.objectid, runtime.objectid),
                    Edge(PermissionEdgeKind.TRUSTS, dev.objectid, agent.objectid),
                ]
            )
        if not agents:
            result.warnings.append(
                "No AI assistants detected at standard install paths. Pass --home to override."
            )
        return agents

    # -- MCP servers and tools -------------------------------------------------

    def _collect_mcp_configs(
        self,
        agents_by_kind: dict[str, Node],
        runtime: Node,
        result: CollectionResult,
    ) -> None:
        for agent_kind, config_path in _mcp_config_paths(self.home):
            if not config_path.exists():
                continue
            try:
                data = json.loads(config_path.read_text())
            except (OSError, json.JSONDecodeError) as e:
                result.warnings.append(f"Could not parse MCP config {config_path}: {e}")
                continue

            mcp_servers = data.get("mcpServers") if isinstance(data, dict) else None
            if not isinstance(mcp_servers, dict):
                continue

            agent = agents_by_kind.get(agent_kind)
            for server_name, server_cfg in mcp_servers.items():
                self._emit_server(server_name, server_cfg, config_path, agent, runtime, result)

    def _emit_server(
        self,
        server_name: str,
        server_cfg: Any,
        config_path: Path,
        agent: Node | None,
        runtime: Node,
        result: CollectionResult,
    ) -> None:
        # Scope: a denied config path takes the whole server off the board.
        if not self.allow_path(config_path, f"mcp:{server_name}"):
            return

        # Classify against the registry. Unknown servers surface as warnings
        # so the user can extend the registry (or override via --known-servers).
        known = self.registry.get(server_name)
        if known is None:
            result.warnings.append(
                f"MCP server '{server_name}' is not in the registry; tools will be tagged "
                f"'unclassified'. Add it to known_mcp_servers.yaml or supply --known-servers."
            )
            tools = ["__unknown__"]
            classification = ["unclassified"]
            provider = "unknown"
        else:
            # Fail soft on a malformed --known-servers overlay: an entry missing
            # a key falls back to the unknown-server defaults rather than raising
            # KeyError mid-scan.
            tools = known.get("tools", ["__unknown__"])
            classification = known.get("classification", ["unclassified"])
            provider = known.get("provider", "unknown")

        # Scope: a denied provider produces no node and no edge for this server.
        if not self.allow_provider(provider, f"mcp:{server_name}"):
            return

        # Infer transport. Local stdio is the default for reference servers;
        # `url` keys indicate HTTP/SSE remotes.
        transport = "stdio"
        if isinstance(server_cfg, dict):
            if "url" in server_cfg:
                transport = "http"
            elif "command" in server_cfg:
                transport = "stdio"

        server = mcp_server_node(server_name, transport=transport, config_source=str(config_path))
        result.nodes.append(server)

        for tool_name in tools:
            tool = mcp_tool_node(server_name, tool_name, classification=classification)
            result.nodes.append(tool)
            result.edges.append(
                Edge(PermissionEdgeKind.EXPOSES, server.objectid, tool.objectid)
            )
            if agent is not None:
                result.edges.append(
                    Edge(PermissionEdgeKind.CALLS_TOOL, agent.objectid, tool.objectid)
                )

        # Server-level NHI: identifier is the server name within the provider
        # so two servers backed by different identities don't collapse.
        nhi = nhi_node(provider=provider, identifier=server_name, nhi_type="mcp_credential")
        result.nodes.append(nhi)
        result.edges.append(
            Edge(PermissionEdgeKind.AUTHENTICATES_AS, server.objectid, nhi.objectid)
        )

        # The credentials a server's config hands it map its real access surface.
        # The runtime can read those creds (generic edge), and recognized env-var
        # *names* are attributed to their provider so a custom server's access
        # (aws, github, stripe, ...) is mapped, not left as a blank "unknown".
        if isinstance(server_cfg, dict):
            env = server_cfg.get("env") or {}
            if env:
                result.edges.append(
                    Edge(
                        PermissionEdgeKind.CAN_READ_CRED,
                        runtime.objectid,
                        nhi.objectid,
                        properties={"via": "mcp_env", "env_keys": sorted(env.keys())},
                    )
                )
                for cred_provider, keys in _providers_from_env(env.keys()).items():
                    if cred_provider == provider:
                        continue  # already the server's own identity
                    if not self.allow_provider(cred_provider, f"mcp:{server_name}:{cred_provider}"):
                        continue  # denied by scope — no node, no edge
                    cred_nhi = nhi_node(
                        provider=cred_provider,
                        identifier=server_name,
                        nhi_type="mcp_env_credential",
                    )
                    result.nodes.append(cred_nhi)
                    result.edges.extend(
                        [
                            Edge(
                                PermissionEdgeKind.AUTHENTICATES_AS,
                                server.objectid,
                                cred_nhi.objectid,
                            ),
                            Edge(
                                PermissionEdgeKind.CAN_READ_CRED,
                                runtime.objectid,
                                cred_nhi.objectid,
                                properties={"via": "mcp_env", "env_keys": sorted(keys)},
                            ),
                        ]
                    )

    # -- Credentials -----------------------------------------------------------

    def _cred_allowed(self, provider: str, path: Path) -> bool:
        """Scope gate for a credential source: provider in scope AND path allowed."""
        return self.allow_provider(provider, str(path)) and self.allow_path(path, str(path))

    def _add_cred_nhi(
        self,
        runtime: Node,
        result: CollectionResult,
        *,
        provider: str,
        identifier: str,
        nhi_type: str,
        via: str,
    ) -> None:
        nhi = nhi_node(provider=provider, identifier=identifier, nhi_type=nhi_type)
        result.nodes.append(nhi)
        result.edges.append(
            Edge(
                PermissionEdgeKind.CAN_READ_CRED,
                runtime.objectid,
                nhi.objectid,
                properties={"via": via},
            )
        )

    def _collect_credentials(self, runtime: Node, result: CollectionResult) -> None:
        # AWS
        for cred_file in (self.home / ".aws" / "credentials", self.home / ".aws" / "config"):
            if not self._cred_allowed("aws", cred_file):
                continue
            for profile in _aws_profile_names(cred_file):
                self._add_cred_nhi(
                    runtime, result, provider="aws", identifier=profile,
                    nhi_type="aws_profile", via=str(cred_file),
                )

        # AWS assume-role topology. ~/.aws/config wires a profile to a role it
        # may assume (role_arn + source_profile) — non-secret config. Emit the
        # role as its own NHI and a CAN_ASSUME edge from the source profile's NHI
        # (same objectid as the profile NHI above, so they join into one node).
        # Topology only; what the role can *do* needs IAM (see the aws-iam collector).
        aws_config = self.home / ".aws" / "config"
        if self._cred_allowed("aws", aws_config):
            for entry in _aws_assume_roles(aws_config):
                source_profile = entry.get("source_profile")
                if not source_profile:
                    continue  # credential_source-only roles have no local source identity
                account_id, role_name, _partition = _parse_role_arn(entry["role_arn"])
                requires_mfa = "mfa_serial" in entry
                role = nhi_node(
                    provider="aws", identifier=entry["role_arn"], nhi_type="assumed_role"
                )
                role.properties["role_name"] = role_name or entry["role_arn"]
                role.properties["requires_mfa"] = requires_mfa
                if account_id:
                    role.properties["account_id"] = account_id
                source = nhi_node(
                    provider="aws", identifier=source_profile, nhi_type="aws_profile"
                )
                result.nodes.extend([source, role])
                result.edges.append(
                    Edge(
                        PermissionEdgeKind.CAN_ASSUME,
                        source.objectid,
                        role.objectid,
                        properties={
                            "requires_mfa": requires_mfa,
                            "account_id": account_id or "unknown",
                            "via": str(aws_config),
                        },
                    )
                )

        # GitHub CLI
        for cred_file in (
            self.home / ".config" / "gh" / "hosts.yml",
            self.home / "AppData" / "Roaming" / "GitHub CLI" / "hosts.yml",
        ):
            if not self._cred_allowed("github", cred_file):
                continue
            for ident in _gh_hosts(cred_file):
                self._add_cred_nhi(
                    runtime, result, provider="github", identifier=ident,
                    nhi_type="gh_cli_token", via=str(cred_file),
                )

        # SSH
        ssh_dir = self.home / ".ssh"
        if self._cred_allowed("ssh", ssh_dir):
            for pub in _ssh_pubkeys(ssh_dir):
                self._add_cred_nhi(
                    runtime, result, provider="ssh", identifier=pub,
                    nhi_type="ssh_keypair", via=str(ssh_dir / pub),
                )

        # Kubernetes
        kube_paths = [self.home / ".kube" / "config"]
        if os.environ.get("KUBECONFIG"):
            kube_paths.append(Path(os.environ["KUBECONFIG"]))
        for cred_file in kube_paths:
            if not self._cred_allowed("kubernetes", cred_file):
                continue
            for ctx in _kube_contexts(cred_file):
                self._add_cred_nhi(
                    runtime, result, provider="kubernetes", identifier=ctx,
                    nhi_type="kube_context", via=str(cred_file),
                )

        # npm
        for cred_file in [self.home / ".npmrc"]:
            if not self._cred_allowed("npm", cred_file):
                continue
            for registry in _npmrc_registries(cred_file):
                self._add_cred_nhi(
                    runtime, result, provider="npm", identifier=registry,
                    nhi_type="npm_registry_auth", via=str(cred_file),
                )

        # Docker / gcloud / azure — presence-only checks.
        for provider, marker in [
            ("docker", self.home / ".docker" / "config.json"),
            ("gcloud", self.home / ".config" / "gcloud" / "credentials.db"),
            ("azure", self.home / ".azure" / "azureProfile.json"),
        ]:
            if not self._cred_allowed(provider, marker):
                continue
            if marker.exists():
                self._add_cred_nhi(
                    runtime, result, provider=provider, identifier="default",
                    nhi_type=f"{provider}_default", via=str(marker),
                )
