from typing import Protocol, Tuple

from .sanitize import sanitize, desanitize
from .errors import FirewallError
from .config import get_master_key_from_env


class LLMCall(Protocol):
    """
    Protocol for an LLM-like callable.

    Anything that implements __call__(text: str) -> str can be used:
      - a real API client
      - a fake function for tests/demos
    """

    def __call__(self, prompt: str) -> str:
        ...


class LLMFirewallClient:
    """
    High-level client that wraps an (untrusted) LLM with the PII firewall:

      user text  -> sanitize()  ->   LLM   -> desanitize()  -> user

    It does not know *how* the LLM works; it only sees a callable.
    """

    def __init__(self, master_key: bytes, llm_call: LLMCall):
        self._master_key = master_key
        self._llm_call = llm_call

    @classmethod
    def from_env(cls, llm_call: LLMCall, *, env_var: str = "PII_FIREWALL_KEY") -> "LLMFirewallClient":
        """
        Convenience constructor that loads the master key from an environment variable.
        """
        key = get_master_key_from_env(env_var)
        return cls(key, llm_call)

    def sanitize_outgoing(self, text: str) -> str:
        """
        Apply the PII firewall to outgoing user text.
        """
        return sanitize(text, self._master_key)

    def desanitize_incoming(self, text: str, *, mode: str = "original") -> str:
        """
        Apply the inverse transformation to LLM replies.

        mode:
          - "original": decrypt tokens and restore plaintext locally
          - "encrypted": leave tokens as-is (no decryption)
        """
        return desanitize(text, self._master_key, mode=mode)

    def ask(self, user_text: str, *, mode: str = "original") -> Tuple[str, str, str]:
        """
        Full roundtrip through the firewall:

          - sanitize user_text
          - send sanitized prompt to LLM
          - desanitize LLM reply

        Returns a triple:
          (sanitized_prompt, raw_llm_reply, final_reply_to_user)
        """
        try:
            sanitized = self.sanitize_outgoing(user_text)
            raw_reply = self._llm_call(sanitized)
            final_reply = self.desanitize_incoming(raw_reply, mode=mode)
            return sanitized, raw_reply, final_reply
        except FirewallError:
            # Let callers handle known firewall errors explicitly
            raise
        except Exception as exc:
            # Unknown errors are wrapped so the app layer can catch one base type
            raise FirewallError("Unexpected error in LLMFirewallClient.ask()") from exc
