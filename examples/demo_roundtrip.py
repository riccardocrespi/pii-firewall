from firewall.sanitize import sanitize, desanitize


def main() -> None:
    key = b"0123456789abcdef0123456789abcdef"  # 32 bytes, demo only

    sample = (
        "My email is john.doe@example.com and my card is 4111 1111 1111 1111. "
        "You can call me at +1 415 555 1234 and send mail to 221B Baker Street, London. "
        "Here is an AWS key AKIAIOSFODNN7EXAMPLE."
    )

    print("Original:")
    print(sample)
    print()

    redacted = sanitize(sample, key)
    print("Redacted (what you send to the LLM):")
    print(redacted)
    print()

    # Pretend this is the LLM's answer
    llm_reply = f"Okay, I will process: {redacted}"
    print("LLM reply (simulated):")
    print(llm_reply)
    print()

    restored = desanitize(llm_reply, key, mode="original")
    print("Desanitized (plaintext restored locally only):")
    print(restored)


if __name__ == "__main__":
    main()
