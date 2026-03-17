#!/usr/bin/env python3
import json
import re
import sys
from typing import Dict, List, Optional

try:
    import requests
except ImportError:
    print("[-] Missing dependency: requests")
    print("[*] Install it with: pip install requests")
    sys.exit(1)


SAMPLES: List[Dict[str, str | int]] = [
    {
        "name": "normal_apple",
        "request": "GET /rest/products/search?q=apple HTTP/1.1",
        "status": 200,
        "response_snippet": '{"status":"success","data":[{"name":"Apple Juice"}]}'
    },
    {
        "name": "normal_banana",
        "request": "GET /rest/products/search?q=banana HTTP/1.1",
        "status": 200,
        "response_snippet": '{"status":"success","data":[{"name":"Banana Juice"}]}'
    },
    {
        "name": "weird_but_benign",
        "request": "GET /rest/products/search?q=apple123 HTTP/1.1",
        "status": 200,
        "response_snippet": '{"status":"success","data":[]}'
    },
    {
        "name": "long_input",
        "request": "GET /rest/products/search?q=aaaaaaaaaaaaaaaaaaaa HTTP/1.1",
        "status": 200,
        "response_snippet": '{"status":"success","data":[]}'
    },
    {
        "name": "quote_breaks_backend",
        "request": "GET /rest/products/search?q=apple%27 HTTP/1.1",
        "status": 500,
        "response_snippet": '{"error":{"message":"SQLITE_ERROR: incomplete input","code":"SQLITE_ERROR"}}'
    },
    {
        "name": "encoded_quote_only",
        "request": "GET /rest/products/search?q=%27 HTTP/1.1",
        "status": 500,
        "response_snippet": '{"error":{"message":"SQLITE_ERROR: incomplete input","code":"SQLITE_ERROR"}}'
    },
    {
        "name": "xss_payload",
        "request": "GET /rest/products/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1",
        "status": 200,
        "response_snippet": '{"status":"success","data":[]}'
    },
    {
        "name": "sqli_classic",
        "request": "GET /rest/products/search?q=%27%20OR%201%3D1-- HTTP/1.1",
        "status": 500,
        "response_snippet": '{"error":{"message":"SQLITE_ERROR: near \\"OR\\"","code":"SQLITE_ERROR"}}'
    },
]


def heuristic_classify(sample: Dict[str, str | int]) -> Dict[str, str]:
    """
    Fallback classifier if no AI model is available.
    """
    request = str(sample["request"]).lower()
    status = int(sample["status"])
    response = str(sample["response_snippet"]).lower()

    score = 0
    reasons: List[str] = []

    suspicious_patterns = [
        (r"%27|'|%22|\"", "contains quote characters commonly used for injection probing"),
        (r"<script>|%3cscript%3e", "contains script tag pattern"),
        (r"\bor\b\s*\d=\d|%20or%20", "contains SQLi-style boolean logic"),
        (r"\.\./", "contains path traversal pattern"),
        (r"--|/\*\*/", "contains SQL comment or obfuscation pattern"),
        (r"alert\s*\(", "contains JavaScript execution pattern"),
    ]

    for pattern, reason in suspicious_patterns:
        if re.search(pattern, request):
            score += 30
            reasons.append(reason)

    if status >= 500:
        score += 35
        reasons.append("server returned 5xx error")

    if "sqlite_error" in response or "sql" in response or "exception" in response:
        score += 40
        reasons.append("response contains backend error details")

    if re.search(r"q=aaaaaaaaaaaa", request):
        score += 10
        reasons.append("input is unusually repetitive")

    if score >= 70:
        label = "malicious"
    elif score >= 30:
        label = "suspicious"
    else:
        label = "normal"

    return {
        "label": label,
        "confidence": str(min(score, 100)),
        "reason": "; ".join(reasons) if reasons else "looks like ordinary search traffic"
    }


def ollama_classify(sample: Dict[str, str | int], model: str = "llama3.1:8b") -> Optional[Dict[str, str]]:
    """
    Uses a local Ollama model for classification.
    Requires:
      - ollama running
      - a pulled model, e.g. ollama pull llama3.1:8b
    """
    prompt = f"""
You are a cybersecurity analyst reviewing web traffic from a training lab.
Classify the event as exactly one of:
- normal
- suspicious
- malicious

Return ONLY valid JSON with keys:
label, confidence, reason

Rules:
- "normal" = ordinary user behavior
- "suspicious" = unusual or malformed but not clearly malicious
- "malicious" = likely attack payload or clearly attack-related behavior
- Consider both the request and the response
- A backend SQL error caused by crafted input should strongly indicate malicious

Event:
Request: {sample["request"]}
HTTP status: {sample["status"]}
Response snippet: {sample["response_snippet"]}
""".strip()

    try:
        resp = requests.post(
            "http://127.0.0.1:11434/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False
            },
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()
        raw = data.get("response", "").strip()

        # Try to parse clean JSON from the model output.
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if not match:
            return None

        parsed = json.loads(match.group(0))
        label = str(parsed.get("label", "")).strip().lower()
        confidence = str(parsed.get("confidence", "")).strip()
        reason = str(parsed.get("reason", "")).strip()

        if label not in {"normal", "suspicious", "malicious"}:
            return None

        return {
            "label": label,
            "confidence": confidence or "unknown",
            "reason": reason or "no reason provided"
        }
    except Exception:
        return None


def classify_sample(sample: Dict[str, str | int], use_ai: bool = True) -> Dict[str, str]:
    if use_ai:
        result = ollama_classify(sample)
        if result:
            result["engine"] = "ollama"
            return result

    result = heuristic_classify(sample)
    result["engine"] = "heuristic"
    return result


def print_result(name: str, sample: Dict[str, str | int], result: Dict[str, str]) -> None:
    label = result["label"].upper()
    engine = result.get("engine", "unknown")
    confidence = result.get("confidence", "unknown")
    reason = result.get("reason", "")

    color = {
        "normal": "\033[92m",
        "suspicious": "\033[93m",
        "malicious": "\033[91m",
    }.get(result["label"], "\033[0m")
    reset = "\033[0m"

    print("=" * 80)
    print(f"Sample: {name}")
    print(f"Request: {sample['request']}")
    print(f"Status:  {sample['status']}")
    print(f"Engine:  {engine}")
    print(f"Verdict: {color}{label}{reset}  (confidence: {confidence})")
    print(f"Reason:  {reason}")


def main() -> None:
    use_ai = True
    if len(sys.argv) > 1 and sys.argv[1] == "--no-ai":
        use_ai = False

    print("[*] Running classifier...\n")
    for sample in SAMPLES:
        result = classify_sample(sample, use_ai=use_ai)
        print_result(str(sample["name"]), sample, result)


if __name__ == "__main__":
    main()
