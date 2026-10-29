"""Interactive chat with the Nordlys HR assistant."""

from app.assistant import ask, load_docs
from app.client import get_settings, make_client

RED, GREEN, YELLOW, RESET = "\033[91m", "\033[92m", "\033[93m", "\033[0m"


def main():
    endpoint, deployment = get_settings()
    client = make_client(endpoint)
    docs = load_docs()
    print(f"Nordlys HR-assistent ({deployment}). Skriv 'exit' for å avslutte.\n")
    while True:
        question = input("Du: ").strip()
        if question.lower() in ("exit", "quit"):
            break
        if not question:
            continue
        result = ask(question, client, deployment, docs=docs)
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
