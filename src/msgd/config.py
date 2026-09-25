"""Minimal INI configuration."""

import configparser
import os
import re
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
    internal_http_timeout_seconds: int = 15
    database: str = "/var/lib/msg-lmm-best/msg.db"
    root_private_key: str = "/etc/msg-lmm-best/root-ca.key"
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

    # Per-identity static web hosting. Empty root derives from the database directory.
    web_root: str = ""
    web_max_site_bytes: int = 10_485_760  # 10 MiB

    # Data-driven topic templates and topics whose create permission is certificate-only.
    topic_template_dir: str = "/etc/msg-lmm-best/templates"
    certificate_only_topics: str = "store,ads"

    # Commerce is data-driven by /store posts; Waffo Pancake only handles checkout/payment.
    commerce_enabled: bool = False
    waffo_base_url: str = "https://api.waffo.ai"
    waffo_merchant_id: str = ""
    waffo_private_key: str = "/etc/msg-lmm-best/commerce/waffo-merchant.pem"
    waffo_webhook_public_key: str = ""
    waffo_onetime_product_id: str = ""
    waffo_subscription_products: str = ""
    waffo_tax_category: str = "digital_goods"
    commerce_checkout_ttl_seconds: int = 900
    commerce_min_price_cents: int = 1
    commerce_max_price_cents: int = 100_000_000
    commerce_min_checkout_ttl_seconds: int = 60
    commerce_max_checkout_ttl_seconds: int = 86_400
    commerce_max_fulfillment_actions: int = 32
    commerce_min_certificate_duration_seconds: int = 60
    commerce_max_certificate_duration_seconds: int = 31_622_400
    commerce_http_timeout_seconds: int = 15
    commerce_webhook_past_tolerance_seconds: int = 2_700
    commerce_webhook_future_tolerance_seconds: int = 60
    commerce_fulfillment_poll_seconds: int = 2
    commerce_allowed_grant_actions: str = (
        "post.create,post.edit.self,post.delete.self,"
        "web.write,web.delete,badge.blue,"
        "file.list,file.create,file.write,file.archive,repo.create,repo.write"
    )
    privacy_policy_file: str = "/etc/msg-lmm-best/privacy.md"
    terms_file: str = "/etc/msg-lmm-best/terms.md"
    # Online commerce CA: a delegated, scope-limited CA. Never expose the Root key to msgd.
    commerce_issuer_private_key: str = "/etc/msg-lmm-best/commerce/issuer.key"
    commerce_issuer_serial: str = ""

    # OpenSSH restricted-shell integration.
    ssh_shell_command: str = "/usr/local/bin/msg-ssh-shell"
    ssh_max_keys_per_identity: int = 16

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
    def local_api_url(self) -> str:
        host = self.host.strip() or "127.0.0.1"
        if host in {"0.0.0.0", "::"}:
            host = "127.0.0.1"
        elif ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"http://{host}:{self.port}"

    @property
    def websub_hubs(self) -> tuple[str, ...]:
        external = tuple(
            part.strip() for part in self.websub_external_hubs.split(",") if part.strip()
        )
        return (f"https://{self.site_name}/hub", *external)

    @property
    def certificate_only_topic_set(self) -> frozenset[str]:
        return frozenset(
            part.strip().lower()
            for part in self.certificate_only_topics.split(",")
            if part.strip()
        )

    @property
    def waffo_subscription_product_map(self) -> dict[str, str]:
        result: dict[str, str] = {}
        for item in self.waffo_subscription_products.split(","):
            key, sep, value = item.strip().partition("=")
            if sep and key and value:
                result[key.strip().lower()] = value.strip()
        return result

    @property
    def commerce_allowed_grant_action_set(self) -> frozenset[str]:
        return frozenset(
            part.strip()
            for part in self.commerce_allowed_grant_actions.split(",")
            if part.strip()
        )

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
            internal_http_timeout_seconds=get(
                "server", "internal_http_timeout_seconds", base.internal_http_timeout_seconds
            ),
            database=get("storage", "database", base.database),
            root_private_key=get("ca", "root_private_key", base.root_private_key),
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
            web_root=get("web", "root", base.web_root),
            web_max_site_bytes=get("web", "max_site_bytes", base.web_max_site_bytes),
            topic_template_dir=get("topics", "template_dir", base.topic_template_dir),
            certificate_only_topics=get(
                "topics", "certificate_only", base.certificate_only_topics
            ),
            commerce_enabled=get("commerce", "enabled", base.commerce_enabled),
            waffo_base_url=get("commerce", "waffo_base_url", base.waffo_base_url),
            waffo_merchant_id=get("commerce", "waffo_merchant_id", base.waffo_merchant_id),
            waffo_private_key=get("commerce", "waffo_private_key", base.waffo_private_key),
            waffo_webhook_public_key=get(
                "commerce", "waffo_webhook_public_key", base.waffo_webhook_public_key
            ),
            waffo_onetime_product_id=get(
                "commerce", "waffo_onetime_product_id", base.waffo_onetime_product_id
            ),
            waffo_subscription_products=get(
                "commerce", "waffo_subscription_products", base.waffo_subscription_products
            ),
            waffo_tax_category=get("commerce", "waffo_tax_category", base.waffo_tax_category),
            commerce_checkout_ttl_seconds=get(
                "commerce", "checkout_ttl_seconds", base.commerce_checkout_ttl_seconds
            ),
            commerce_min_price_cents=get(
                "commerce", "min_price_cents", base.commerce_min_price_cents
            ),
            commerce_max_price_cents=get(
                "commerce", "max_price_cents", base.commerce_max_price_cents
            ),
            commerce_min_checkout_ttl_seconds=get(
                "commerce",
                "min_checkout_ttl_seconds",
                base.commerce_min_checkout_ttl_seconds,
            ),
            commerce_max_checkout_ttl_seconds=get(
                "commerce",
                "max_checkout_ttl_seconds",
                base.commerce_max_checkout_ttl_seconds,
            ),
            commerce_max_fulfillment_actions=get(
                "commerce",
                "max_fulfillment_actions",
                base.commerce_max_fulfillment_actions,
            ),
            commerce_min_certificate_duration_seconds=get(
                "commerce",
                "min_certificate_duration_seconds",
                base.commerce_min_certificate_duration_seconds,
            ),
            commerce_max_certificate_duration_seconds=get(
                "commerce",
                "max_certificate_duration_seconds",
                base.commerce_max_certificate_duration_seconds,
            ),
            commerce_http_timeout_seconds=get(
                "commerce", "http_timeout_seconds", base.commerce_http_timeout_seconds
            ),
            commerce_webhook_past_tolerance_seconds=get(
                "commerce",
                "webhook_past_tolerance_seconds",
                base.commerce_webhook_past_tolerance_seconds,
            ),
            commerce_webhook_future_tolerance_seconds=get(
                "commerce",
                "webhook_future_tolerance_seconds",
                base.commerce_webhook_future_tolerance_seconds,
            ),
            commerce_fulfillment_poll_seconds=get(
                "commerce", "fulfillment_poll_seconds", base.commerce_fulfillment_poll_seconds
            ),
            commerce_allowed_grant_actions=get(
                "commerce", "allowed_grant_actions", base.commerce_allowed_grant_actions
            ),
            privacy_policy_file=get(
                "commerce", "privacy_policy_file", base.privacy_policy_file
            ),
            terms_file=get("commerce", "terms_file", base.terms_file),
            commerce_issuer_private_key=get(
                "commerce", "issuer_private_key", base.commerce_issuer_private_key
            ),
            commerce_issuer_serial=get(
                "commerce", "issuer_serial", base.commerce_issuer_serial
            ),
            ssh_shell_command=get("ssh", "shell_command", base.ssh_shell_command),
            ssh_max_keys_per_identity=get(
                "ssh", "max_keys_per_identity", base.ssh_max_keys_per_identity
            ),
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
            "internal_http_timeout_seconds",
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
            "web_max_site_bytes",
            "ssh_max_keys_per_identity",
            "commerce_checkout_ttl_seconds",
            "commerce_min_price_cents",
            "commerce_max_price_cents",
            "commerce_min_checkout_ttl_seconds",
            "commerce_max_checkout_ttl_seconds",
            "commerce_max_fulfillment_actions",
            "commerce_min_certificate_duration_seconds",
            "commerce_max_certificate_duration_seconds",
            "commerce_http_timeout_seconds",
            "commerce_webhook_past_tolerance_seconds",
            "commerce_webhook_future_tolerance_seconds",
            "commerce_fulfillment_poll_seconds",
        ):
            if getattr(self, key) < 1:
                raise SystemExit(f"{key} must be >= 1")
        if not self.ssh_shell_command.strip():
            raise SystemExit("ssh_shell_command must not be empty")
        if any(char in self.ssh_shell_command for char in '"\r\n'):
            raise SystemExit("ssh_shell_command contains unsafe characters")
        if self.default_limit > self.max_limit:
            raise SystemExit("default_limit must not exceed max_limit")
        if self.commerce_min_price_cents > self.commerce_max_price_cents:
            raise SystemExit("commerce min_price_cents must not exceed max_price_cents")
        if self.commerce_min_checkout_ttl_seconds > self.commerce_max_checkout_ttl_seconds:
            raise SystemExit(
                "commerce min_checkout_ttl_seconds must not exceed max_checkout_ttl_seconds"
            )
        if (
            self.commerce_min_certificate_duration_seconds
            > self.commerce_max_certificate_duration_seconds
        ):
            raise SystemExit(
                "commerce min_certificate_duration_seconds must not exceed "
                "max_certificate_duration_seconds"
            )
        if self.websub_default_lease_seconds > self.websub_max_lease_seconds:
            raise SystemExit(
                "websub_default_lease_seconds must not exceed websub_max_lease_seconds"
            )
        hubs = [part.strip() for part in self.websub_external_hubs.split(",") if part.strip()]
        if len(hubs) != len(set(hubs)):
            raise SystemExit("websub external_hubs must not contain duplicates")
        if not self.valkey_prefix.strip():
            raise SystemExit("valkey_prefix must not be empty")
        topic_re = re.compile(r"^[a-z][a-z0-9]{1,23}$")
        if any(not topic_re.fullmatch(name) for name in self.certificate_only_topic_set):
            raise SystemExit("topics.certificate_only contains an invalid topic name")
        if self.commerce_enabled:
            if not self.waffo_base_url.startswith("https://"):
                raise SystemExit("commerce.waffo_base_url must use https")
            if not self.waffo_merchant_id.strip():
                raise SystemExit("commerce.waffo_merchant_id is required when commerce is enabled")
            if not self.waffo_webhook_public_key.strip():
                raise SystemExit(
                    "commerce.waffo_webhook_public_key is required when commerce is enabled"
                )
            if not self.waffo_onetime_product_id and not self.waffo_subscription_product_map:
                raise SystemExit(
                    "commerce requires waffo_onetime_product_id or waffo_subscription_products"
                )
            if not self.commerce_issuer_serial.strip():
                raise SystemExit("commerce.issuer_serial is required when commerce is enabled")
