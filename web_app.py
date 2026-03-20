"""
Pact Sentinel Web UI — Flask Backend
Provides a REST API + serves the frontend SPA.

Endpoints:
  POST /api/analyze       — Analyze Pact source code
  GET  /api/rules         — List available rules
  GET  /api/health        — Health check
  GET  /                  — Frontend SPA
"""
import os
import sys
import json
import time
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory

sys.path.insert(0, str(Path(__file__).parent))
from src.core.analyzer import PactSentinel

app = Flask(__name__, static_folder="web", static_url_path="")

# ── API ───────────────────────────────────────────────────────────

@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(force=True)
    source = data.get("source", "")
    filename = data.get("filename", "contract.pact")
    use_ai = data.get("use_ai", False)
    api_key = data.get("api_key", "") or os.environ.get("ANTHROPIC_API_KEY", "")
    severity = data.get("severity_filter")
    skip_rules = data.get("skip_rules", [])
    confidence = float(data.get("confidence", 0.5))

    if not source.strip():
        return jsonify({"error": "No source code provided"}), 400
    if len(source) > 100_000:
        return jsonify({"error": "Source too large (max 100KB)"}), 413

    sentinel = PactSentinel(
        api_key=api_key,
        use_ai=use_ai and bool(api_key),
        severity_filter=severity,
        skip_rules=skip_rules if skip_rules else None,
        confidence_threshold=confidence,
    )

    result = sentinel.analyze_source(source, filename=filename)
    return jsonify(result.report)


@app.route("/api/rules", methods=["GET"])
def list_rules():
    from src.rules.rule_engine import ALL_RULES
    return jsonify([
        {
            "id": r.rule_id,
            "title": r.title,
            "severity": r.severity.value,
            "tags": r.tags,
        }
        for r in ALL_RULES
    ])


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "tool": "pact-sentinel", "version": "1.0.0"})


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_spa(path):
    web_dir = Path(__file__).parent / "web"
    if path and (web_dir / path).exists():
        return send_from_directory(str(web_dir), path)
    return send_from_directory(str(web_dir), "index.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    debug = os.environ.get("DEBUG", "false").lower() == "true"
    print(f"🛡️  Pact Sentinel Web UI → http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=debug)
