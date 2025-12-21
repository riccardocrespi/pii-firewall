# firewall/errors.py

class FirewallError(Exception):
    """Base class for all firewall-specific errors."""
    pass


class CryptoError(FirewallError):
    """Errors originating from the cryptographic layer (encryption/decryption)."""
    pass


class DetectionError(FirewallError):
    """Errors originating from PII detection (regex/ML)."""
    pass


class SanitizationError(FirewallError):
    """Errors in the sanitize/desanitize pipeline."""
    pass
