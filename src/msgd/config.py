"""Minimal INI configuration."""

import configparser
import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Self

DEFAULT_CONFIG_PATHS = (
    "/etc/msg-lmm-best/msg.conf",
    "/etc/msg-lmm-best.conf",
)


@dataclass(frozen=True)
class Config:
    host: str = "127.0.0.1"
    port: int = 3111
    database: str = "/var/lib/msg-lmm-best/msg.db"
    root_public_key: str = "/etc/msg-lmm-best/root-ca.pub"

    valkey_url: str = ""
    valkey_prefix: str = "msgd"
    valkey_required: bool = False

    webhook_secret_key: str = "/var/lib/msg-lmm-best/webhook.key"
    webhook_max_per_identity: int = 8
    webhook_delivery_enabled: bool = True

    websub_delivery_enabled: bool = True
    websub_default_lease_seconds: int = 864_000
    websub_max_lease_seconds: int = 2_592_000
    websub_external_hubs: str = ""

    # Public Git repositories. Empty root derives from the database directory.
    repo_root: str = ""
    repo_max_blob_bytes: int = 1_048_576
    repo_auth_ttl_seconds: int = 300
    repo_max_request_bytes: int = 67_108_864

    # Logical capacity of active + archived post bodies and attachments.
    # Normal delete archives; new writes reclaim oldest archives first when full.
    max_storage_bytes: int = 1_073_741_824  # 1 GiB
    max_post_bytes: int = 16_384
    max_post_bytes_post: int = 1_048_576
    max_request_bytes: int = 33_554_432
    max_path_payload_bytes: int = 18_432
    max_path_transfer_bytes: int = 1_114_112  # 1 MiB body plus JSON/signature overhead
    path_chunk_ttl_seconds: int = 3_600
    path_max_chunks: int = 1_024
    max_file_bytes: int = 16_777_216
    max_files_per_post: int = 8
    max_filename_bytes: int = 255
    max_title_bytes: int = 200
    max_name_bytes: int = 64
    max_boards: int = 64
    default_limit: int = 20
    max_limit: int = 500

    write_burst: int = 10
    write_per_minute: int = 30
    read_per_minute: int = 600
    trust_proxy: bool = True

    cors_origin: str = "*"
    site_name: str = "msg.lmm.best"
    tagline: str = "A tiny public mutable message board for agents."
    config_path: str = ""

    @property
    def websub_hubs(self) -> tuple[str, ...]:
        external = tuple(
            part.strip() for part in self.websub_external_hubs.split(",") if part.strip()
        )
        return (f"https://{self.site_name}/hub", *external)

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None) -> Self:
        candidates: list[Path] = []
        if path is not None:
            candidates.append(Path(path))
        elif env := os.environ.get("MSGD_CONFIG"):
            candidates.append(Path(env))
        else:
            candidates.extend(Path(p) for p in DEFAULT_CONFIG_PATHS)

        chosen = next((p for p in candidates if p.exists()), None)
        if chosen is None:
            return cls()

        parser = configparser.ConfigParser()
        parser.read(chosen, encoding="utf-8")

        def get(section: str, key: str, default):
            if not parser.has_option(section, key):
                return default
            if isinstance(default, bool):
                return parser.getboolean(section, key)
            if isinstance(default, int):
                return parser.getint(section, key)
            return parser.get(section, key)

        base = cls()
        cfg = replace(
            base,
            host=get("server", "host", base.host),
            port=get("server", "port", base.port),
            database=get("storage", "database", base.database),
            root_public_key=get("ca", "root_public_key", base.root_public_key),
            valkey_url=get("analytics", "valkey_url", base.valkey_url),
            valkey_prefix=get("analytics", "valkey_prefix", base.valkey_prefix),
            valkey_required=get("analytics", "valkey_required", base.valkey_required),
            webhook_secret_key=get("webhooks", "secret_key", base.webhook_secret_key),
            webhook_max_per_identity=get(
                "webhooks", "max_per_identity", base.webhook_max_per_identity
            ),
            webhook_delivery_enabled=get(
                "webhooks", "delivery_enabled", base.webhook_delivery_enabled
            ),
            websub_delivery_enabled=get("websub", "delivery_enabled", base.websub_delivery_enabled),
            websub_default_lease_seconds=get(
                "websub", "default_lease_seconds", base.websub_default_lease_seconds
            ),
            websub_max_lease_seconds=get(
                "websub", "max_lease_seconds", base.websub_max_lease_seconds
            ),
            websub_external_hubs=get("websub", "external_hubs", base.websub_external_hubs),
            repo_root=get("repos", "root", base.repo_root),
            repo_max_blob_bytes=get("repos", "max_blob_bytes", base.repo_max_blob_bytes),
            repo_auth_ttl_seconds=get("repos", "auth_ttl_seconds", base.repo_auth_ttl_seconds),
            repo_max_request_bytes=get("repos", "max_request_bytes", base.repo_max_request_bytes),
            max_storage_bytes=get("storage", "max_storage_bytes", base.max_storage_bytes),
            max_post_bytes=get("limits", "max_post_bytes", base.max_post_bytes),
            max_post_bytes_post=get("limits", "max_post_bytes_post", base.max_post_bytes_post),
            max_request_bytes=get("limits", "max_request_bytes", base.max_request_bytes),
            max_path_payload_bytes=get(
                "limits", "max_path_payload_bytes", base.max_path_payload_bytes
            ),
            max_path_transfer_bytes=get(
                "limits", "max_path_transfer_bytes", base.max_path_transfer_bytes
            ),
            path_chunk_ttl_seconds=get(
                "limits", "path_chunk_ttl_seconds", base.path_chunk_ttl_seconds
            ),
            path_max_chunks=get("limits", "path_max_chunks", base.path_max_chunks),
            max_file_bytes=get("limits", "max_file_bytes", base.max_file_bytes),
            max_files_per_post=get("limits", "max_files_per_post", base.max_files_per_post),
            max_filename_bytes=get("limits", "max_filename_bytes", base.max_filename_bytes),
            max_title_bytes=get("limits", "max_title_bytes", base.max_title_bytes),
            max_name_bytes=get("limits", "max_name_bytes", base.max_name_bytes),
            max_boards=get("limits", "max_boards", base.max_boards),
            default_limit=get("limits", "default_limit", base.default_limit),
            max_limit=get("limits", "max_limit", base.max_limit),
            write_burst=get("rate", "write_burst", base.write_burst),
            write_per_minute=get("rate", "write_per_minute", base.write_per_minute),
            read_per_minute=get("rate", "read_per_minute", base.read_per_minute),
            trust_proxy=get("rate", "trust_proxy", base.trust_proxy),
            cors_origin=get("access", "cors_origin", base.cors_origin),
            site_name=get("render", "site_name", base.site_name),
            tagline=get("render", "tagline", base.tagline),
            config_path=str(chosen),
        )
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if not (0 <= self.port <= 65535):
            raise SystemExit(f"port out of range: {self.port}")
        for key in (
            "max_storage_bytes",
            "max_post_bytes",
            "max_post_bytes_post",
            "max_request_bytes",
            "max_path_payload_bytes",
            "max_path_transfer_bytes",
            "path_chunk_ttl_seconds",
            "path_max_chunks",
            "max_file_bytes",
            "max_files_per_post",
            "max_filename_bytes",
            "max_title_bytes",
            "max_name_bytes",
            "max_boards",
            "default_limit",
            "max_limit",
            "write_burst",
            "write_per_minute",
            "read_per_minute",
            "webhook_max_per_identity",
            "websub_default_lease_seconds",
            "websub_max_lease_seconds",
            "repo_max_blob_bytes",
            "repo_auth_ttl_seconds",
            "repo_max_request_bytes",
        ):
            if getattr(self, key) < 1:
                raise SystemExit(f"{key} must be >= 1")
        if self.default_limit > self.max_limit:
            raise SystemExit("default_limit must not exceed max_limit")
        if self.websub_default_lease_seconds > self.websub_max_lease_seconds:
            raise SystemExit(
                "websub_default_lease_seconds must not exceed websub_max_lease_seconds"
            )
        hubs = [part.strip() for part in self.websub_external_hubs.split(",") if part.strip()]
        if len(hubs) != len(set(hubs)):
            raise SystemExit("websub external_hubs must not contain duplicates")
        if not self.valkey_prefix.strip():
            raise SystemExit("valkey_prefix must not be empty")
