from flask import Flask, jsonify, request
from pathlib import Path
import os

from src.dns_filter.filter_rules import FilterRules

CONFIG_PATH = Path(os.path.join(os.getcwd(), "config", "blocked_domains.txt"))
rules = FilterRules(CONFIG_PATH)

app = Flask(__name__)


@app.route("/api/rules", methods=["GET"])
def list_rules():
    # read file and return lines
    if not CONFIG_PATH.exists():
        return jsonify([])
    data = [l for l in CONFIG_PATH.read_text(encoding="utf-8").splitlines() if l and not l.startswith("#")]
    return jsonify(data)


@app.route("/api/rules", methods=["POST"])
def add_rule():
    body = request.get_json() or {}
    domain = body.get("domain")
    if not domain:
        return jsonify({"error": "domain required"}), 400
    rules.add(domain)
    return jsonify({"ok": True})


@app.route("/api/rules", methods=["DELETE"])
def remove_rule():
    body = request.get_json() or {}
    domain = body.get("domain")
    if not domain:
        return jsonify({"error": "domain required"}), 400
    rules.remove(domain)
    return jsonify({"ok": True})


@app.route("/api/reload", methods=["POST"])
def reload_rules():
    rules.reload()
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
