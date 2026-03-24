from flask import Flask, request, Response, send_from_directory, jsonify
import httpx
import concurrent.futures

import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=BASE_DIR)

API_BASE = "https://garotacomlocal.com/wp-json"
SITE_BASE = "https://garotacomlocal.com"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
}


@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "explorador.html")


@app.route("/api/<path:path>")
def proxy(path):
    url = f"{API_BASE}/{path}"
    params = dict(request.args)
    try:
        with httpx.Client(timeout=30, follow_redirects=True, verify=True) as client:
            resp = client.get(url, params=params, headers=HEADERS)
            excluded = ["content-encoding", "transfer-encoding", "connection"]
            headers = {k: v for k, v in resp.headers.items() if k.lower() not in excluded}
            headers["Access-Control-Allow-Origin"] = "*"
            return Response(resp.content, status=resp.status_code, headers=headers)
    except Exception as e:
        return Response(f'{{"error":"{e}"}}', status=500, content_type="application/json")


@app.route("/scan-hidden")
def scan_hidden():
    """Scan a range of media IDs for hidden (401) items and reveal via oEmbed."""
    start = int(request.args.get("start", 1))
    end = int(request.args.get("end", start + 100))
    end = min(end, start + 500)  # max 500 per request

    results = {"hidden": [], "public": 0, "not_found": 0, "scanned": 0}

    def check_id(mid):
        try:
            with httpx.Client(timeout=8, headers=HEADERS, verify=True) as client:
                r = client.get(f"{API_BASE}/wp/v2/media/{mid}", params={"_fields": "id,status,source_url,title"})
                if r.status_code == 401:
                    # oEmbed bypass
                    oembed = client.get(
                        f"{API_BASE}/oembed/1.0/embed",
                        params={"url": f"{SITE_BASE}/?attachment_id={mid}"}
                    )
                    info = {"id": mid, "status": "hidden"}
                    if oembed.status_code == 200:
                        data = oembed.json()
                        info["title"] = data.get("title", "")
                        info["author"] = data.get("author_name", "")
                        info["author_url"] = data.get("author_url", "")
                        # Try to guess the file URL from the title
                        title = info["title"]
                        if title:
                            info["guessed_url"] = guess_url(title)
                    return ("hidden", info)
                elif r.status_code == 200:
                    data = r.json()
                    return ("public", {
                        "id": mid,
                        "status": "public",
                        "title": data.get("title", {}).get("rendered", ""),
                        "source_url": data.get("source_url", "")
                    })
                else:
                    return ("not_found", None)
        except:
            return ("error", None)

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(check_id, mid): mid for mid in range(start, end + 1)}
        for future in concurrent.futures.as_completed(futures):
            result_type, info = future.result()
            results["scanned"] += 1
            if result_type == "hidden":
                results["hidden"].append(info)
            elif result_type == "public":
                results["public"] += 1
            else:
                results["not_found"] += 1

    results["hidden"].sort(key=lambda x: x["id"])
    return jsonify(results)


def guess_url(title):
    """Try to reconstruct file URL from oEmbed title."""
    import re
    name = title.strip()
    # Remove parenthetical numbers like (1), (2)
    name_clean = re.sub(r'\s*\(\d+\)\s*', '', name)
    # Common upload paths
    paths = [
        "2025/09", "2024/10", "2024/08", "2024/06", "2024/12",
        "2025/11", "2025/10", "2025/12", "2026/01", "2026/02", "2026/03",
        "2024/01", "2024/02", "2024/04", "2023/09", "2023/08",
        "2019/06", "2022/02", "2022/04"
    ]
    # Normalize title to filename patterns
    fname = name.lower().replace(" ", "-").replace("–", "-").replace("(", "").replace(")", "")
    fname = re.sub(r'-+', '-', fname).strip("-")
    guesses = []
    for ext in [".jpeg", ".jpg", ".mp4", ".png"]:
        for path in paths[:5]:
            guesses.append(f"https://static.garotacomlocal.com/wp-content/uploads/{path}/{fname}{ext}")
    return guesses


@app.route("/check-url")
def check_url():
    """Check if a guessed URL exists on the server."""
    url = request.args.get("url", "")
    if not url:
        return jsonify({"exists": False})
    try:
        with httpx.Client(timeout=8, headers=HEADERS, follow_redirects=True, verify=True) as client:
            r = client.head(url)
            if r.status_code == 200:
                return jsonify({
                    "exists": True,
                    "url": url,
                    "size": int(r.headers.get("content-length", 0)),
                    "type": r.headers.get("content-type", "")
                })
    except:
        pass
    return jsonify({"exists": False})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"GCL Explorer rodando em http://localhost:{port}")
    app.run(host="0.0.0.0", port=port)
