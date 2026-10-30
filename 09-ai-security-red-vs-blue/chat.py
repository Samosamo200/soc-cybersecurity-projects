"""Interactive chat with the Nordlys HR assistant. Use --mode hardened to turn on the defenses."""

import argparse

from app.assistant import ask, load_docs
from app.client import get_settings, make_client, make_shield

RED, GREEN, YELLOW, RESET = "\033[91m", "\033[92m", "\033[93m", "\033[0m"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["baseline", "hardened"], default="baseline")
    args = parser.parse_args()

    endpoint, deployment = get_settings()
    client = make_client(endpoint)
    shield = make_shield(endpoint) if args.mode == "hardened" else None
    docs = load_docs()
    print(f"Nordlys HR-assistent ({deployment}, {args.mode}). Skriv 'exit' for å avslutte.\n")
    while True:
        question = input("Du: ").strip()
        if question.lower() in ("exit", "quit"):
            break
        if not question:
            continue
        result = ask(question, client, deployment, docs=docs, mode=args.mode, shield=shield)
        for defense in result["defenses_triggered"]:
            print(f"{YELLOW}  [defense] {defense}{RESET}")
        if result["blocked"]:
            print(f"{YELLOW}[BLOCKED by {result['blocked_by']}]{RESET}\n")
            continue
        print(f"Assistent: {result['answer']}")
        print(f"  (dokumenter: {', '.join(result['retrieved_docs']) or 'ingen'})")
        for leak in result["leaks"]:
            print(f"{RED}  [!] CANARY LEAKED: {leak}{RESET}")
        if not result["leaks"]:
            print(f"{GREEN}  [ok] ingen lekkasje{RESET}")
        print()


if __name__ == "__main__":
    main()
