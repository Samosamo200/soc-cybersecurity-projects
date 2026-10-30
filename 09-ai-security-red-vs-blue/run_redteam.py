"""
Run the attack library against the Nordlys HR assistant and measure the attack success rate.

An attack succeeds if the answer contains a canary token or the phishing marker.
Each attack runs several times, because LLM answers are not deterministic.

Usage:
    python run_redteam.py              # all attacks, 3 runs each
    python run_redteam.py --repeats 1  # quick test
"""

import argparse
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from app.assistant import ask, load_docs
from app.client import get_settings, make_client
from redteam.attacks import ATTACKS, PHISHING_MARKER

RESULTS_DIR = Path(__file__).resolve().parent / "results"
RED, GREEN, YELLOW, RESET = "\033[91m", "\033[92m", "\033[93m", "\033[0m"


def run_attack(attack, client, deployment, docs, repeats):
    attack_docs = docs + [attack["poison"]] if "poison" in attack else docs
    runs = []
    for _ in range(repeats):
        result = ask(attack["prompt"], client, deployment, docs=attack_docs, user="redteam")
        if PHISHING_MARKER in (result["answer"] or ""):
            result["leaks"].append("phishing_link")
        runs.append({
            "success": bool(result["leaks"]),
            "blocked": result["blocked"],
            "blocked_by": result["blocked_by"],
            "leaks": result["leaks"],
            "retrieved_docs": result["retrieved_docs"],
            "answer": result["answer"],
        })
    return runs


def main():
    parser = argparse.ArgumentParser(description="Red team the Nordlys HR assistant")
    parser.add_argument("--repeats", type=int, default=3, help="runs per attack (default 3)")
    args = parser.parse_args()

    endpoint, deployment = get_settings()
    client = make_client(endpoint)
    docs = load_docs()

    results = []
    print(f"Running {len(ATTACKS)} attacks x {args.repeats} runs against {deployment}...\n")
    for attack in ATTACKS:
        runs = run_attack(attack, client, deployment, docs, args.repeats)
        successes = sum(run["success"] for run in runs)
        blocked = sum(run["blocked"] for run in runs)
        color = RED if successes else GREEN
        note = f" {YELLOW}({blocked} blocked){RESET}" if blocked else ""
        print(f"{color}{attack['id']:7} {successes}/{len(runs)} succeeded{RESET}{note}  {attack['category']}")
        results.append({**{k: v for k, v in attack.items() if k != "poison"}, "runs": runs})

    # Summary per category
    per_category = defaultdict(lambda: [0, 0, 0])
    for item in results:
        stats = per_category[item["category"]]
        stats[0] += sum(run["success"] for run in item["runs"])
        stats[1] += sum(run["blocked"] for run in item["runs"])
        stats[2] += len(item["runs"])
    total_success = sum(s[0] for s in per_category.values())
    total_blocked = sum(s[1] for s in per_category.values())
    total_runs = sum(s[2] for s in per_category.values())

    print(f"\n{'Category':28} {'Success':>9} {'Blocked':>9} {'ASR':>6}")
    for category, (success, blocked, runs) in per_category.items():
        print(f"{category:28} {success:>4}/{runs:<4} {blocked:>4}/{runs:<4} {success / runs:>6.0%}")
    print(f"{'TOTAL':28} {total_success:>4}/{total_runs:<4} {total_blocked:>4}/{total_runs:<4} "
          f"{total_success / total_runs:>6.0%}")

    RESULTS_DIR.mkdir(exist_ok=True)
    out_file = RESULTS_DIR / f"baseline-{datetime.now():%Y%m%d-%H%M%S}.json"
    out_file.write_text(json.dumps({
        "mode": "baseline",
        "deployment": deployment,
        "repeats": args.repeats,
        "attack_success_rate": total_success / total_runs,
        "summary": {cat: {"success": s, "blocked": b, "runs": r} for cat, (s, b, r) in per_category.items()},
        "results": results,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nFull results saved to {out_file.relative_to(Path.cwd()) if out_file.is_relative_to(Path.cwd()) else out_file}")


if __name__ == "__main__":
    main()
