"""
PactGuard Web UI — Flask Backend
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
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ── Logger Setup ──────────────────────────────────────────────────
class Tee:
    def __init__(self, stream, filepath):
        self.stream = stream
        self.filepath = filepath
        
    def write(self, data):
        self.stream.write(data)
        self.stream.flush()
        try:
            with open(self.filepath, "a", encoding="utf-8") as f:
                f.write(data)
        except:
            pass
            
    def flush(self):
        self.stream.flush()

log_file = Path(__file__).parent / "server.log"
sys.stdout = Tee(sys.stdout, log_file)
sys.stderr = Tee(sys.stderr, log_file)

sys.path.insert(0, str(Path(__file__).parent))
from src.core.analyzer import PactGuard

app = Flask(__name__, static_folder="web", static_url_path="")
CORS(app, resources={r"/api/*": {"origins": "*"}})

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# ── Exception & Log Routes ────────────────────────────────────────
@app.errorhandler(Exception)
def handle_exception(e):
    import traceback
    if hasattr(e, "code"):
        return jsonify({"error": str(e)}), e.code
    traceback.print_exc()
    return jsonify({
        "error": "Unhandled Exception",
        "message": str(e),
        "traceback": traceback.format_exc()
    }), 500

@app.route("/api/debug_logs", methods=["GET"])
@limiter.exempt
def get_debug_logs():
    log_path = Path(__file__).parent / "server.log"
    if log_path.exists():
        with open(log_path, "r", encoding="utf-8") as f:
            return f.read(), 200, {"Content-Type": "text/plain; charset=utf-8"}
    return "No log file found", 404

# ── API ───────────────────────────────────────────────────────────

@app.route("/api/analyze", methods=["POST"])
@limiter.limit("10 per minute;60 per hour")
def analyze():
    data = request.get_json(force=True)
    source        = data.get("source", "")
    filename      = data.get("filename", "contract.pact")
    use_ai        = data.get("use_ai", False)
    api_key       = data.get("api_key", "")
    openai_key    = data.get("openai_key", "")   or os.environ.get("OPENAI_API_KEY",    "")
    gemini_key = data.get("gemini_key", "") or os.environ.get("GEMINI_API_KEY", "")
    # Legacy: single api_key field auto-detects provider
    if api_key and not openai_key and not gemini_key:
        if api_key.startswith("AIza"):
            gemini_key = api_key
        else:
            openai_key = api_key
    ai_provider   = data.get("ai_provider")
    severity      = data.get("severity_filter")
    skip_rules    = data.get("skip_rules", [])
    confidence    = float(data.get("confidence", 0.5))

    any_key = bool(openai_key or gemini_key)

    if not source.strip():
        return jsonify({"error": "No source code provided"}), 400
    if len(source) > 100_000:
        return jsonify({"error": "Source too large (max 100KB)"}), 413

    try:
        sentinel = PactGuard(
            openai_key=openai_key or None,
            gemini_key=gemini_key or None,
            ai_provider=ai_provider,
            use_ai=use_ai and any_key,
            severity_filter=severity,
            skip_rules=skip_rules if skip_rules else None,
            confidence_threshold=confidence,
        )

        result = sentinel.analyze_source(source, filename=filename)
        return jsonify(result.report)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e), "traceback": traceback.format_exc()}), 500


@app.route("/api/rules", methods=["GET"])
@limiter.exempt
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
@limiter.exempt
def health():
    return jsonify({"status": "ok", "tool": "pact-guard", "version": "1.0.0"})


# ── Swagger API Docs & Specification ─────────────────────────────────

@app.route("/api/swagger.json", methods=["GET"])
@limiter.exempt
def swagger_json():
    return jsonify({
        "openapi": "3.0.3",
        "info": {
            "title": "PactGuard Security Analyzer API",
            "description": "API documentation for the AI-powered Kadena Pact smart contract security analyzer.",
            "version": "1.0.0",
            "contact": {
                "name": "PactGuard Contributors",
                "url": "https://github.com/sunilblinkoninfra-cyber/pact-guard"
            }
        },
        "paths": {
            "/api/health": {
                "get": {
                    "summary": "Health Check",
                    "description": "Returns the status and version of the PactGuard service.",
                    "responses": {
                        "200": {
                            "description": "Service is healthy and online",
                            "content": {
                                "application/json": {
                                    "example": {
                                        "status": "ok",
                                        "tool": "pact-guard",
                                        "version": "1.0.0"
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/rules": {
                "get": {
                    "summary": "List Rules",
                    "description": "Retrieves the list of all 12 smart contract security rules supported by the analyzer.",
                    "responses": {
                        "200": {
                            "description": "Successful retrieval of rules list",
                            "content": {
                                "application/json": {
                                    "example": [
                                        {
                                            "id": "R-001",
                                            "title": "State Mutation Without Capability Guard",
                                            "severity": "critical",
                                            "tags": ["access-control", "capability", "state-mutation"]
                                        }
                                    ]
                                }
                            }
                        }
                    }
                }
            },
            "/api/debug_logs": {
                "get": {
                    "summary": "Get Debug Logs",
                    "description": "Retrieves the remote server stdout/stderr debug logs for active troubleshooting.",
                    "responses": {
                        "200": {
                            "description": "Log contents retrieved successfully"
                        },
                        "404": {
                            "description": "Log file not found"
                        }
                    }
                }
            },
            "/api/analyze": {
                "post": {
                    "summary": "Analyze Pact Smart Contract",
                    "description": "Runs static parsing, applies 12 security rules, scores the contract risk, and optionally enriches findings using Gemini AI.",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "source": {
                                            "type": "string",
                                            "description": "Full source code of the Pact smart contract"
                                        },
                                        "filename": {
                                            "type": "string",
                                            "description": "Optional custom filename for the report",
                                            "default": "contract.pact"
                                        },
                                        "use_ai": {
                                            "type": "boolean",
                                            "description": "Set to true to run Gemini AI reasoning",
                                            "default": False
                                        },
                                        "openai_key": {
                                            "type": "string",
                                            "description": "Optional user-supplied OpenAI API key"
                                        },
                                        "gemini_key": {
                                            "type": "string",
                                            "description": "Optional user-supplied Gemini API key"
                                        },
                                        "confidence": {
                                            "type": "number",
                                            "description": "Minimum confidence threshold (0.0 to 1.0)",
                                            "default": 0.5
                                        }
                                    },
                                    "required": ["source"]
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Smart contract analysis was successful",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object"
                                    }
                                }
                            }
                        },
                        "400": {
                            "description": "Bad Request (e.g. empty source code)"
                        },
                        "413": {
                            "description": "Payload Too Large (source code exceeds 100KB)"
                        },
                        "429": {
                            "description": "Too Many Requests (rate limit reached)"
                        },
                        "500": {
                            "description": "Internal Server Error (auditing parser/AI crash)"
                        }
                    }
                }
            }
        }
    })


@app.route("/apidocs", methods=["GET"])
@limiter.exempt
def apidocs():
    swagger_ui_html = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>PactGuard API Documentation</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
  <link rel="icon" type="image/png" href="https://unpkg.com/swagger-ui-dist@5/favicon-32x32.png" sizes="32x32" />
  <style>
    html { box-sizing: border-box; overflow: -y-scroll; }
    *, *:before, *:after { box-sizing: inherit; }
    body { margin: 0; background: #fafafa; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-standalone-preset.js"></script>
  <script>
    window.onload = () => {
      window.ui = SwaggerUIBundle({
        url: '/api/swagger.json',
        dom_id: '#swagger-ui',
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        layout: "BaseLayout",
        deepLinking: true,
        showExtensions: true,
        showCommonExtensions: true
      });
    };
  </script>
</body>
</html>
"""
    return swagger_ui_html, 200, {"Content-Type": "text/html"}


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
@limiter.exempt
def serve_spa(path):
    web_dir = Path(__file__).parent / "web"
    if path and (web_dir / path).exists():
        return send_from_directory(str(web_dir), path)
    return send_from_directory(str(web_dir), "index.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    debug = os.environ.get("DEBUG", "false").lower() == "true"
    
    if debug:
        print(f"🛡️  PactGuard Web UI (Flask Debug) → http://localhost:{port}")
        app.run(host="0.0.0.0", port=port, debug=True)
    else:
        try:
            from waitress import serve
            print(f"🛡️  PactGuard Web UI (Production Waitress WSGI) → http://localhost:{port}")
            serve(app, host="0.0.0.0", port=port)
        except ImportError:
            print(f"🛡️  PactGuard Web UI (Flask Production Fallback) → http://localhost:{port}")
            app.run(host="0.0.0.0", port=port, debug=False)
