import os

from .errors import FirewallError

MIN_KEY_LEN = 32  # bytes, for AES-256-GCM


class ConfigError(FirewallError):
    """Raised when configuration (e.g. key) is invalid or missing."""
    pass


def get_master_key_from_env(var_name: str = "PII_FIREWALL_KEY") -> bytes:
    """
    Load the master key from an environment variable.

    The key is interpreted as a UTF-8 string and must be at least MIN_KEY_LEN bytes.
    In real deployments you might want to load this from a secrets manager instead.
    """
    value = os.getenv(var_name)
    if not value:
        raise ConfigError(f"{var_name} is not set")

    key_bytes = value.encode("utf-8")
    if len(key_bytes) < MIN_KEY_LEN:
        raise ConfigError(
            f"{var_name} must be at least {MIN_KEY_LEN} bytes when UTF-8 encoded"
        )

    return key_bytes
