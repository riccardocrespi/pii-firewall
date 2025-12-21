import argparse
import logging

from firewall.client import LLMFirewallClient
from firewall.errors import FirewallError



# To run a test prompt:
#   python cli.py "My email is john.doe@example.com and my card is 4111 1111 1111 1111."
# Try encrypted mode:
#   python cli.py --mode encrypted "My phone is +1 415 555 1234."
# If you want logs:
#   python cli.py -v "Here is an AWS key AKIAIOSFODNN7EXAMPLE."



def fake_llm_call(prompt: str) -> str:
    """
    Very simple stand-in for a real LLM.

    In a real app, you'd replace this with a function that calls an
    external API (OpenAI, Anthropic, etc.).
    """
    # For the demo, just echo the prompt with some decoration
    return f"[FAKE LLM REPLY] I received: {prompt}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PII Firewall demo CLI wrapping an LLM-like backend.",
    )
    parser.add_argument(
        "prompt",
        help="User prompt to send through the firewall",
    )
    parser.add_argument(
        "--mode",
        choices=["original", "encrypted"],
        default="original",
        help=(
            "How to handle PII in the reply: "
            "'original' decrypts tokens locally, 'encrypted' keeps tokens as-is."
        ),
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable debug logging.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        client = LLMFirewallClient.from_env(fake_llm_call)

        sanitized, raw_reply, final_reply = client.ask(
            args.prompt,
            mode=args.mode,
        )

        print("=== Original user input ===")
        print(args.prompt)
        print()

        print("=== Sanitized prompt sent to LLM ===")
        print(sanitized)
        print()

        print("=== Raw LLM reply ===")
        print(raw_reply)
        print()

        print("=== Final reply presented to user ===")
        print(final_reply)
        print()

    except FirewallError as exc:
        logging.error("Firewall error: %s", exc)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
