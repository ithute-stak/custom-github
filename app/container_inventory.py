from __future__ import annotations

import os
import posixpath
import shlex
import sqlite3
from collections import Counter, defaultdict
from typing import Any, Callable

from fastapi import FastAPI, HTTPException

from app.deployment import ssh_command

_EMPTY_LABELS = {"", "<no value>", "<nil>", "null", "None"}


def _clean_label(value: str) -> str:
    value = (value or "").strip()
    return "" if value in _EMPTY_LABELS else value


def _canonical(value: str) -> str:
    return "-".join(part for part in value.lower().replace("_", "-").split("-") if part)


def _container_role(image: str, service: str, name: str) -> str:
    text = f"{image} {service} {name}".lower()
    groups = [
        ("database", ("postgres", "postgis", "mysql", "mariadb", "mongo", "mssql", "sqlserver")),
        ("cache-queue", ("redis", "valkey", "rabbitmq", "memcached", "kafka", "zookeeper")),
        ("proxy", ("nginx", "traefik", "caddy", "haproxy", "gateway", "proxy")),
        ("mail", ("postfix", "dovecot", "roundcube", "rspamd", "clamav", "mailserver", "webmail")),
        ("monitoring", ("prometheus", "grafana", "loki", "cadvisor", "node-exporter", "uptime", "watchtower")),
    ]
    for role, words in groups:
        if any(word in text for word in words):
            return role
    return "application"


def _managed_context(connection: sqlite3.Connection, server_id: int) -> dict[str, Any]:
    projects = connection.execute("SELECT id, name FROM projects ORDER BY id").fetchall()
    targets = connection.execute(
        """
        SELECT p.id AS project_id, p.name AS project_name, t.compose_dir, t.service_name
        FROM deployment_targets t
        JOIN projects p ON p.id = t.project_id
        WHERE t.server_id = ?
        ORDER BY p.id
        """,
        (server_id,),
    ).fetchall()
    aliases: dict[str, dict[str, Any]] = {}
    by_dir: dict[str, dict[str, Any]] = {}
    for row in projects:
        item = {"project_id": int(row["id"]), "project_name": str(row["name"]), "targeted": False}
        aliases[_canonical(str(row["name"]))] = item
    for row in targets:
        item = {
            "project_id": int(row["project_id"]),
            "project_name": str(row["project_name"]),
            "targeted": True,
            "compose_dir": str(row["compose_dir"]),
            "service_name": str(row["service_name"]),
        }
        compose_dir = posixpath.normpath(str(row["compose_dir"]))
        by_dir[compose_dir] = item
        aliases[_canonical(str(row["project_name"]))] = item
        aliases[_canonical(posixpath.basename(compose_dir))] = item
    return {"aliases": aliases, "by_dir": by_dir}


def _parse_inventory(output: str, context: dict[str, Any]) -> dict[str, Any]:
    aliases: dict[str, dict[str, Any]] = context.get("aliases", {})
    by_dir: dict[str, dict[str, Any]] = context.get("by_dir", {})
    containers: list[dict[str, Any]] = []

    for raw in output.splitlines():
        if not raw.strip():
            continue
        parts = raw.split("\t")
        if len(parts) < 8:
            continue
        container_id, name, image, compose_project, compose_service, working_dir, status, ports = parts[:8]
        compose_project = _clean_label(compose_project)
        compose_service = _clean_label(compose_service)
        working_dir = _clean_label(working_dir)
        match: dict[str, Any] | None = None
        match_reason: str | None = None
        if working_dir:
            normalized_dir = posixpath.normpath(working_dir)
            if normalized_dir in by_dir:
                match = by_dir[normalized_dir]
                match_reason = "deployment target directory"
        if match is None and compose_project:
            match = aliases.get(_canonical(compose_project))
            if match is not None:
                match_reason = "registered project name"

        relation = "registered-project" if match else ("unregistered-stack" if compose_project else "unmanaged")
        role = _container_role(image, compose_service, name)
        containers.append(
            {
                "id": container_id,
                "name": name.lstrip("/"),
                "image": image,
                "compose_project": compose_project or None,
                "compose_service": compose_service or None,
                "working_dir": working_dir or None,
                "status": status,
                "ports": ports,
                "role": role,
                "relation": relation,
                "registered_project": match.get("project_name") if match else None,
                "project_id": match.get("project_id") if match else None,
                "targeted": bool(match and match.get("targeted")),
                "match_reason": match_reason,
            }
        )

    stacks: dict[str, dict[str, Any]] = {}
    for item in containers:
        stack_name = item["compose_project"] or "Unmanaged / no Compose project"
        stack = stacks.setdefault(
            stack_name,
            {
                "name": stack_name,
                "relation": item["relation"],
                "registered_project": item["registered_project"],
                "project_id": item["project_id"],
                "container_count": 0,
                "roles": Counter(),
                "images": set(),
                "services": set(),
            },
        )
        stack["container_count"] += 1
        stack["roles"][item["role"]] += 1
        stack["images"].add(item["image"])
        if item["compose_service"]:
            stack["services"].add(item["compose_service"])
        if stack["relation"] != "registered-project" and item["relation"] == "registered-project":
            stack["relation"] = "registered-project"
            stack["registered_project"] = item["registered_project"]
            stack["project_id"] = item["project_id"]

    stack_rows: list[dict[str, Any]] = []
    for stack in stacks.values():
        stack_rows.append(
            {
                **{k: v for k, v in stack.items() if k not in {"roles", "images", "services"}},
                "roles": dict(stack["roles"]),
                "images": sorted(stack["images"]),
                "services": sorted(stack["services"]),
                "review_required": stack["relation"] != "registered-project",
            }
        )
    stack_rows.sort(key=lambda row: (row["review_required"], -row["container_count"], row["name"].lower()))

    role_counts = Counter(item["role"] for item in containers)
    relation_counts = Counter(item["relation"] for item in containers)
    return {
        "total_running": len(containers),
        "registered_project_running": relation_counts["registered-project"],
        "unregistered_stack_running": relation_counts["unregistered-stack"],
        "unmanaged_running": relation_counts["unmanaged"],
        "review_required_running": relation_counts["unregistered-stack"] + relation_counts["unmanaged"],
        "compose_stack_count": len([row for row in stack_rows if row["name"] != "Unmanaged / no Compose project"]),
        "registered_stack_count": len([row for row in stack_rows if row["relation"] == "registered-project"]),
        "role_counts": dict(role_counts),
        "stacks": stack_rows,
        "containers": sorted(containers, key=lambda row: ((row["compose_project"] or "~").lower(), row["name"].lower())),
        "note": "Review-required means the running container is not mapped to a registered Custom GitHub project. It is not automatically unsafe or disposable.",
    }


def install_container_inventory_routes(
    app: FastAPI,
    *,
    db_factory: Callable[[], sqlite3.Connection],
    server_lookup: Callable[[int], sqlite3.Row],
) -> None:
    @app.get("/api/vps/servers/{server_id}/docker/inventory")
    def docker_inventory(server_id: int) -> dict[str, Any]:
        server = dict(server_lookup(server_id))
        command = r"""
docker ps --no-trunc --format '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Label "com.docker.compose.project"}}\t{{.Label "com.docker.compose.service"}}\t{{.Label "com.docker.compose.project.working_dir"}}\t{{.Status}}\t{{.Ports}}'
""".strip()
        code, output = ssh_command(server, command, timeout=45)
        if code != 0:
            raise HTTPException(status_code=502, detail=output.strip()[-4000:] or "Unable to inspect Docker containers")
        with db_factory() as connection:
            context = _managed_context(connection, server_id)
        result = _parse_inventory(output, context)
        result["server_id"] = server_id
        result["server_name"] = server["name"]
        return result


__all__ = ["_canonical", "_container_role", "_parse_inventory", "install_container_inventory_routes"]
