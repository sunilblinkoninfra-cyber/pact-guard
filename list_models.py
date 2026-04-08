import urllib.request
import os
import json
key = os.environ.get("GEMINI_API_KEY", "AIzaSyDKtZiiyP-g2w0z5s6qncBFr8e9aXi1mEY")
url = f"https://generativelanguage.googleapis.com/v1beta/models?key={key}"
req = urllib.request.Request(url)
try:
    with urllib.request.urlopen(req) as r:
        data = json.loads(r.read())
    for m in data.get("models", []):
        methods = m.get("supportedGenerationMethods", [])
        if "generateContent" in methods:
            print(m.get("name"))
except Exception as e:
    print("Error:", e)
