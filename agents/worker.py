import json, time, requests, os, signal
from redis import Redis

r = Redis(host=os.getenv("REDIS_HOST","redis"), port=6379, decode_responses=True)

class TimeoutException(Exception): pass
def handler(signum, frame): raise TimeoutException()

def safe_head(url, timeout_sec=8):
    try:
        signal.signal(signal.SIGALRM, handler)
        signal.alarm(timeout_sec)
        resp = requests.head(url, timeout=timeout_sec, allow_redirects=True)
        signal.alarm(0)
        return {"ok": True, "status_code": resp.status_code}
    except TimeoutException:
        return {"ok": False, "error": "timeout"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def score_url(url):
    suspicious_keywords = ['verify','account','secure','login','update','confirm']
    return sum(1 for k in suspicious_keywords if k in (url or "").lower())

while True:
    item = r.brpop("scan_queue", timeout=5)
    if not item:
        continue
    _, raw = item
    job = json.loads(raw)
    job["attempts"] += 1
    result = safe_head(job["url"])
    if not result["ok"] and job["attempts"] < 3:
        time.sleep(2 ** job["attempts"])
        r.lpush("scan_queue", json.dumps(job))
        continue
    verdict = "malicious" if result.get("ok") and score_url(job["url"]) > 0 else \
              ("unknown" if not result["ok"] else "clean")
    job["result"] = {"verdict": verdict, **result}
    r.lpush("results", json.dumps(job))
    print(f"Processed {job['job_id']} -> {verdict}")
