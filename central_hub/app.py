from flask import Flask, request, jsonify
from redis import Redis
import json, time, os

app = Flask(__name__)
r = Redis(host=os.getenv("REDIS_HOST","redis"), port=6379, decode_responses=True)

@app.route("/health")
def health():
    return jsonify({"ok": True, "ts": time.time()})

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json() or {}
    job = {
        "job_id": f"job-{int(time.time()*1000)}",
        "url": data.get("url"),
        "submitted_by": data.get("user","demo"),
        "ts": time.time(),
        "attempts": 0
    }
    r.lpush("scan_queue", json.dumps(job))
    return jsonify({"status":"accepted","job_id": job["job_id"]}), 202

@app.route("/results", methods=["GET"])
def results():
    items = r.lrange("results", 0, 49)
    parsed = [json.loads(x) for x in items]
    return jsonify(parsed)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

