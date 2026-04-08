#!/usr/bin/env python3
"""
pact-guard CLI
AI-powered security analyzer for Kadena Pact smart contracts.
"""
import sys
import os
import json
import argparse
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.core.analyzer import PactGuard


def build_parser():
    p = argparse.ArgumentParser(
        prog="pact-guard",
        description="🛡️  AI-powered security analyzer for Kadena Pact smart contracts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          python cli.py mytoken.pact
          python cli.py mytoken.pact --format json
          python cli.py --dir ./contracts --format json
          python cli.py mytoken.pact --severity critical,high
          cat file.pact | python cli.py -
          python cli.py mytoken.pact --format sarif -o results.sarif
          python cli.py mytoken.pact --exit-code
        """),
    )
    p.add_argument("file", nargs="?", default=None,
                   help="Path to .pact file or '-' for stdin")
    p.add_argument("--dir", "-d", metavar="DIRECTORY",
                   help="Analyze all .pact files in a directory")
    p.add_argument("--format", "-f",
                   choices=["cli", "json", "markdown", "sarif"], default="cli")
    p.add_argument("--output", "-o", metavar="FILE")
    p.add_argument("--severity", "-s", metavar="LEVEL",
                   help="Filter: critical,high,medium,low")
    p.add_argument("--tags", "-t", metavar="TAGS")
    p.add_argument("--skip-rules", metavar="RULES")
    p.add_argument("--no-ai", action="store_true")
    p.add_argument("--api-key",       metavar="KEY",      help="API key — OpenAI (sk-...) or Gemini (AIza...). Auto-detects provider.")
    p.add_argument("--openai-key",    metavar="KEY",      help="OpenAI API key (or OPENAI_API_KEY env var)")
    p.add_argument("--gemini-key", metavar="KEY",      help="Gemini API key (or GEMINI_API_KEY env var)")
    p.add_argument("--ai-provider",   metavar="PROVIDER", choices=["openai","gemini"], help="Force AI provider")
    p.add_argument("--exit-code", action="store_true")
    p.add_argument("--fail-on", choices=["critical","high","medium","low"], default="high")
    p.add_argument("--confidence", type=float, default=0.5)
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--summary", action="store_true",
                   help="One-line: grade, score, counts (for shell scripting)")
    p.add_argument("--list-rules", action="store_true")
    p.add_argument("--version", action="version", version="pact-guard 1.0.0")
    return p


def list_rules():
    from src.rules.rule_engine import ALL_RULES
    print("\n🛡️  PactGuard — Available Rules\n")
    print(f"{'ID':<10} {'Severity':<10} {'Tags':<40} Title")
    print("─" * 90)
    for r in ALL_RULES:
        tags = ", ".join(r.tags[:3])
        print(f"{r.rule_id:<10} {r.severity.value:<10} {tags:<40} {r.title}")
    print()


def should_fail(findings, fail_on):
    order = ["low", "medium", "high", "critical"]
    threshold = order.index(fail_on)
    return any(order.index(f.severity.value) >= threshold for f in findings)


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.list_rules:
        list_rules()
        sys.exit(0)

    severity_filter = None
    if args.severity and "," not in args.severity:
        severity_filter = args.severity.strip()

    tag_filter = [t.strip() for t in args.tags.split(",")] if args.tags else None
    skip_rules = [r.strip() for r in args.skip_rules.split(",")] if args.skip_rules else None
    api_key = args.api_key or os.environ.get("GEMINI_API_KEY")

    openai_key    = getattr(args, 'openai_key',    None) or os.environ.get("OPENAI_API_KEY",    "")
    gemini_key = getattr(args, 'gemini_key', None) or os.environ.get("GEMINI_API_KEY", "")
    ai_provider   = getattr(args, 'ai_provider',   None)

    sentinel = PactGuard(
        api_key=api_key,
        openai_key=openai_key or None,
        gemini_key=gemini_key or None,
        ai_provider=ai_provider,
        use_ai=not args.no_ai,
        severity_filter=severity_filter,
        tag_filter=tag_filter,
        skip_rules=skip_rules,
        confidence_threshold=args.confidence,
    )
    # Show which AI provider will be used
    if not args.no_ai and not getattr(args, 'summary', False):
        info = sentinel.ai.get_provider_info()
        if info['available'] == 'True':
            import sys
            print(f"  AI: {info['provider'].upper()} ({info['model']}) {info['key_prefix']}", file=sys.stderr)

    if args.dir:
        results = sentinel.analyze_directory(args.dir)
    elif args.file == "-":
        source = sys.stdin.read()
        results = [sentinel.analyze_source(source, filename="<stdin>")]
    elif args.file:
        results = [sentinel.analyze_file(args.file)]
    else:
        print("Error: specify a file, '--dir', or '-' for stdin.", file=sys.stderr)
        sys.exit(1)

    if args.severity and "," in args.severity:
        allowed = {s.strip() for s in args.severity.split(",")}
        for r in results:
            r.findings = [f for f in r.findings if f.severity.value in allowed]

    if len(results) == 1:
        r = results[0]
        if args.format == "json":
            output = r.as_json()
        elif args.format == "markdown":
            output = r.as_markdown()
        elif args.format == "sarif":
            output = r.as_sarif()
        else:
            output = r.as_cli(color=not args.no_color)
    else:
        if args.format == "json":
            output = json.dumps([r.report for r in results], indent=2)
        else:
            parts = []
            for r in results:
                if args.format == "markdown":
                    parts.append(r.as_markdown())
                elif args.format == "sarif":
                    parts.append(r.as_sarif())
                else:
                    parts.append(r.as_cli(color=not args.no_color))
            output = "\n\n".join(parts)

    # Handle --summary before full output
    if getattr(args, 'summary', False):
        for r in results:
            rs = r.risk_score
            bd = rs.breakdown
            print(f"{rs.letter_grade} | {rs.normalized:.0f}/100 | "
                  f"crit={bd['critical']} high={bd['high']} med={bd['medium']} low={bd['low']} | "
                  f"{r.report.get('analyzed_file','?')}")
        return

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"✅  Report written to {args.output}", file=sys.stderr)
    else:
        print(output)

    if args.exit_code:
        all_findings = [f for r in results for f in r.findings]
        if should_fail(all_findings, args.fail_on):
            sys.exit(1)


if __name__ == "__main__":
    main()
