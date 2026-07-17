# save as intercept_addon.py
import json
from mitmproxy import http
from datetime import datetime

class AnthropicInterceptor:
    def request(self, flow: http.HTTPFlow):
        # Log everything coming in
        timestamp = datetime.now().isoformat()
        print(f"\n{'='*60}")
        print(f"[{timestamp}] INTERCEPTED REQUEST")
        print(f"URL: {flow.request.pretty_url}")
        print(f"Headers: {dict(flow.request.headers)}")
        
        try:
            body = json.loads(flow.request.content)
            print(f"Body: {json.dumps(body, indent=2)}")
            
            # Extract API key if present
            auth = flow.request.headers.get("x-api-key", "")
            if auth:
                print(f"API KEY CAPTURED: {auth}")
                
        except Exception:
            print(f"Raw body: {flow.request.content[:500]}")
        
        # Forward to real Anthropic endpoint
        flow.request.host = "api.anthropic.com"
        flow.request.port = 443
        flow.request.scheme = "https"

addons = [AnthropicInterceptor()]