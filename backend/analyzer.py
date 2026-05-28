import re
import requests
from typing import Dict, Any, List
from urllib.parse import urlparse

# Standard browser user-agent to prevent bot-blocking policies
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

def normalize_url(url: str) -> str:
    """
    Validates and normalizes the input URL.
    Adds https:// if scheme is missing.
    """
    url = url.strip()
    if not url:
        raise ValueError("URL cannot be empty")
    
    # Check if a scheme is present, if not prepends https://
    if not re.match(r'^https?://', url, re.IGNORECASE):
        url = "https://" + url

    parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError("Invalid domain name or URL format")
        
    return url

def analyze_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Analyzes the HTTP headers and generates a detailed report.
    Returns status, values, score, and educational content.
    """
    # Normalize header keys to lowercase for case-insensitive lookup
    lower_headers = {k.lower(): v for k, v in headers.items()}
    
    results = {}
    total_score = 0
    max_total_score = 100

    # 1. Content-Security-Policy (CSP) (25 points)
    csp_val = lower_headers.get("content-security-policy")
    csp_status = "danger"
    csp_score = 0
    csp_rec = "Configure a Content-Security-Policy header. A basic starting policy is: default-src 'self';"
    
    if csp_val:
        # Check if the policy contains dangerous wildcards or unsafe flags in script/default directives
        is_weak = False
        weakness_reasons = []
        
        # Simple heuristic check for unsafe policy configurations
        if "*" in csp_val:
            is_weak = True
            weakness_reasons.append("contains wildcard '*' wildcard source")
        if "'unsafe-inline'" in csp_val.lower():
            is_weak = True
            weakness_reasons.append("allows inline scripts ('unsafe-inline')")
        if "'unsafe-eval'" in csp_val.lower():
            is_weak = True
            weakness_reasons.append("allows script execution evaluation ('unsafe-eval')")
        if "http:" in csp_val.lower():
            is_weak = True
            weakness_reasons.append("allows loading resources over insecure HTTP")
            
        if is_weak:
            csp_status = "warning"
            csp_score = 12
            csp_rec = f"CSP is defined, but it is weak because it {', '.join(weakness_reasons)}. Tighten the policy by removing unsafe sources and avoiding wildcards."
        else:
            csp_status = "good"
            csp_score = 25
            csp_rec = "CSP is present and correctly configured to prevent unauthorized content execution."

    results["Content-Security-Policy"] = {
        "value": headers.get("Content-Security-Policy") or headers.get("content-security-policy"),
        "status": csp_status,
        "score_contribution": csp_score,
        "max_score": 25,
        "beginner_explanation": "CSP is like a security guard for web browsers. It tells the browser exactly which domains are allowed to load and execute scripts, stylesheets, or images on your website.",
        "security_impact": "Prevents Cross-Site Scripting (XSS) and data injection attacks by ensuring only trusted, pre-approved scripts can run.",
        "real_world_example": "Without CSP, if an attacker finds an input field vulnerable to XSS, they can inject code to fetch malicious files: <script src='http://attacker.com/steal.js'></script>. A strict CSP immediately blocks this loading.",
        "recommendation": csp_rec,
        "exam_tip": "For SY0-701, understand CSP as a crucial defense-in-depth mitigation against Cross-Site Scripting (XSS) and clickjacking. Know that it defines approved resource origins."
    }
    total_score += csp_score

    # 2. Strict-Transport-Security (HSTS) (20 points)
    hsts_val = lower_headers.get("strict-transport-security")
    hsts_status = "danger"
    hsts_score = 0
    hsts_rec = "Enable HSTS on the web server with a max-age of at least 1 year (31536000 seconds) and include subdomains: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    
    if hsts_val:
        # Check max-age
        max_age_match = re.search(r'max-age\s*=\s*(\d+)', hsts_val, re.IGNORECASE)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age >= 31536000:
                hsts_status = "good"
                hsts_score = 20
                hsts_rec = "HSTS is present and configured with a secure duration of 1 year or more."
            else:
                hsts_status = "warning"
                hsts_score = 10
                hsts_rec = f"HSTS max-age is set to {max_age} seconds, which is less than the recommended 1 year (31536000 seconds)."
        else:
            hsts_status = "warning"
            hsts_score = 10
            hsts_rec = "HSTS header exists, but the max-age directive was not found or is misconfigured."

    results["Strict-Transport-Security"] = {
        "value": headers.get("Strict-Transport-Security") or headers.get("strict-transport-security"),
        "status": hsts_status,
        "score_contribution": hsts_score,
        "max_score": 20,
        "beginner_explanation": "HSTS acts like an 'HTTPS-Only' enforcement rule. It instructs the browser that the website must only be accessed using secure HTTPS connections, rejecting any insecure HTTP requests.",
        "security_impact": "Prevents Man-in-the-Middle (MITM) attacks, protocol downgrade attacks (like SSL stripping), and cookie hijacking.",
        "real_world_example": "If a user types 'http://mybank.com' on a public airport Wi-Fi, an attacker can intercept the request. With HSTS, the browser automatically swaps the request to 'https://mybank.com' before sending it over the network, rendering interception impossible.",
        "recommendation": hsts_rec,
        "exam_tip": "SY0-701 objective check: HSTS forces HTTPS. It addresses SSL stripping / downgrade attacks, which fall under network security and secure protocol design."
    }
    total_score += hsts_score

    # 3. X-Frame-Options (15 points)
    xfo_val = lower_headers.get("x-frame-options")
    xfo_status = "danger"
    xfo_score = 0
    xfo_rec = "Set X-Frame-Options header on your server. Use 'DENY' to block framing completely, or 'SAMEORIGIN' to only allow framing by your own site."
    
    if xfo_val:
        xfo_val_clean = xfo_val.upper().strip()
        if "DENY" in xfo_val_clean or "SAMEORIGIN" in xfo_val_clean:
            xfo_status = "good"
            xfo_score = 15
            xfo_rec = f"X-Frame-Options is set to '{xfo_val}' which successfully prevents Clickjacking attacks."
        else:
            xfo_status = "warning"
            xfo_score = 5
            xfo_rec = f"X-Frame-Options is set to '{xfo_val}', which is obsolete or weak. Use DENY or SAMEORIGIN."

    results["X-Frame-Options"] = {
        "value": headers.get("X-Frame-Options") or headers.get("x-frame-options"),
        "status": xfo_status,
        "score_contribution": xfo_score,
        "max_score": 15,
        "beginner_explanation": "This header prevents your website from being embedded inside a frame or iframe on another website. It ensures nobody can overlay buttons on your site to trick your users.",
        "security_impact": "Mitigates Clickjacking attacks where users are tricked into clicking buttons they did not intend to.",
        "real_world_example": "An attacker creates a website showing a 'Win a free car' button. Beneath that button, they embed your bank site in an invisible iframe. Clicking 'Win' actually clicks 'Transfer Funds'. X-Frame-Options blocks this framing.",
        "recommendation": xfo_rec,
        "exam_tip": "SY0-701 Exam Topic: Clickjacking. X-Frame-Options (or CSP frame-ancestors directive) is the primary technical control used to defend against Clickjacking."
    }
    total_score += xfo_score

    # 4. X-Content-Type-Options (15 points)
    xcto_val = lower_headers.get("x-content-type-options")
    xcto_status = "danger"
    xcto_score = 0
    xcto_rec = "Add the X-Content-Type-Options header with the exact value 'nosniff'."
    
    if xcto_val and "nosniff" in xcto_val.lower():
        xcto_status = "good"
        xcto_score = 15
        xcto_rec = "X-Content-Type-Options is set to 'nosniff' to prevent MIME-sniffing vulnerabilities."

    results["X-Content-Type-Options"] = {
        "value": headers.get("X-Content-Type-Options") or headers.get("x-content-type-options"),
        "status": xcto_status,
        "score_contribution": xcto_score,
        "max_score": 15,
        "beginner_explanation": "This header stops browsers from guessing ('sniffing') the type of a file. It forces the browser to obey whatever file type the server claims (e.g. text/javascript, image/png).",
        "security_impact": "Prevents MIME-sniffing attacks, where a browser is tricked into executing an uploaded file (like a profile image) as executable JavaScript.",
        "real_world_example": "An application allows users to upload custom images. An attacker uploads a file named 'avatar.png' containing JavaScript. Without 'nosniff', a browser might inspect ('sniff') the content, see it's script, and run it, executing XSS.",
        "recommendation": xcto_rec,
        "exam_tip": "Understand that 'nosniff' prevents MIME sniffing, which is a key browser exploitation technique where text or multimedia files are executed as code."
    }
    total_score += xcto_score

    # 5. Referrer-Policy (10 points)
    ref_val = lower_headers.get("referrer-policy")
    ref_status = "warning"  # Default status if missing is warning since browsers have secure defaults now, but it should be explicit.
    ref_score = 4
    ref_rec = "Configure the Referrer-Policy header. The industry standard recommendation is: Referrer-Policy: strict-origin-when-cross-origin"
    
    if ref_val:
        ref_val_clean = ref_val.lower().strip()
        safe_policies = [
            "no-referrer",
            "no-referrer-when-downgrade",
            "origin",
            "origin-when-cross-origin",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin"
        ]
        if ref_val_clean in safe_policies:
            ref_status = "good"
            ref_score = 10
            ref_rec = f"Referrer-Policy is set to '{ref_val}' which is a safe policy."
        elif "unsafe-url" in ref_val_clean:
            ref_status = "danger"
            ref_score = 0
            ref_rec = "Referrer-Policy is set to 'unsafe-url', which leaks the full URL to third parties. Replace this with strict-origin-when-cross-origin."
        else:
            ref_status = "warning"
            ref_score = 5
            ref_rec = f"Referrer-Policy is set to '{ref_val}', which may leak sensitive information. Adjust to strict-origin-when-cross-origin."

    results["Referrer-Policy"] = {
        "value": headers.get("Referrer-Policy") or headers.get("referrer-policy"),
        "status": ref_status,
        "score_contribution": ref_score,
        "max_score": 10,
        "beginner_explanation": "This header controls how much referrer information (the URL of the page you came from) is shared when you click a link pointing to another website.",
        "security_impact": "Protects user privacy and leaks of sensitive query parameters (such as access tokens or reset passwords) to third-party domains.",
        "real_world_example": "If your reset URL is 'site.com/reset?token=abc', and your page links to an external image, the external server receives 'site.com/reset?token=abc' in the 'Referer' header. Referrer-Policy trims this to just 'site.com'.",
        "recommendation": ref_rec,
        "exam_tip": "Referrer-Policy plays a role in data privacy and data leakage prevention (DLP). In security assessments, ensuring referrer details don't leak secrets is critical."
    }
    total_score += ref_score

    # 6. Permissions-Policy (10 points)
    perm_val = lower_headers.get("permissions-policy")
    perm_status = "warning"
    perm_score = 0
    perm_rec = "Add the Permissions-Policy header to restrict access to sensitive APIs. Example: Permissions-Policy: camera=(), microphone=(), geolocation=()"
    
    if perm_val:
        perm_status = "good"
        perm_score = 10
        perm_rec = "Permissions-Policy is present, restricting access to browser features."

    results["Permissions-Policy"] = {
        "value": headers.get("Permissions-Policy") or headers.get("permissions-policy"),
        "status": perm_status,
        "score_contribution": perm_score,
        "max_score": 10,
        "beginner_explanation": "This header controls which browser features and hardware APIs (like camera, microphone, geolocation, or USB) the page and any embedded frames are allowed to access.",
        "security_impact": "Minimizes the site's attack surface. If an attacker injects malicious script, they are still blocked from accessing the user's physical camera or location.",
        "real_world_example": "If a simple blog site is hacked, the hacker might inject a script to open the user's camera. If the server has set Permissions-Policy: camera=(), the browser blocks camera access immediately.",
        "recommendation": perm_rec,
        "exam_tip": "Permissions-Policy relates to the principle of Least Privilege. Restricting client-side capabilities prevents web apps from abusing host device permissions."
    }
    total_score += perm_score

    # 7. X-XSS-Protection (5 points)
    xss_val = lower_headers.get("x-xss-protection")
    xss_status = "warning"
    xss_score = 0
    xss_rec = "X-XSS-Protection is legacy. For maximum protection on old browsers, set it to: X-XSS-Protection: 1; mode=block. However, ensure a strong CSP is implemented for modern browsers."
    
    if xss_val:
        xss_val_clean = xss_val.lower().replace(" ", "")
        if "1;mode=block" in xss_val_clean:
            xss_status = "good"
            xss_score = 5
            xss_rec = "X-XSS-Protection is set to '1; mode=block', which successfully enables blocking on older browsers."
        elif xss_val_clean == "0":
            # 0 is sometimes explicitly recommended if using a strong CSP to avoid client-side exploitation of the XSS filter itself.
            # We'll treat it as a warning but explain it.
            xss_status = "warning"
            xss_score = 3
            xss_rec = "X-XSS-Protection is disabled ('0'). This is acceptable if you have a robust Content-Security-Policy (CSP) in place."
        else:
            xss_status = "warning"
            xss_score = 2
            xss_rec = f"X-XSS-Protection is set to '{xss_val}'. Recommended setting is '1; mode=block' for legacy compatibility."

    results["X-XSS-Protection"] = {
        "value": headers.get("X-XSS-Protection") or headers.get("x-xss-protection"),
        "status": xss_status,
        "score_contribution": xss_score,
        "max_score": 5,
        "beginner_explanation": "This is an older header designed to enable the built-in XSS filter in legacy browsers (like Internet Explorer). Modern browsers ignore it in favor of Content-Security-Policy.",
        "security_impact": "Stops reflected XSS attacks from loading in older browsers.",
        "real_world_example": "An attacker creates a malicious link pointing to your site with script payloads in the search parameters. If a user clicks it, the browser detects the echoed script, stops the page, and blocks execution.",
        "recommendation": xss_rec,
        "exam_tip": "Legacy relevance: Although deprecated, SY0-701 objectives still reference X-XSS-Protection. The classic secure configuration is '1; mode=block' to prevent Reflected XSS."
    }
    total_score += xss_score

    # 8. Access-Control-Allow-Origin (CORS) (5 points)
    cors_val = lower_headers.get("access-control-allow-origin")
    cors_status = "good"  # Default: missing is safe (defaults to same-origin)
    cors_score = 5
    cors_rec = "No CORS headers are present, which defaults to secure same-origin behavior."
    
    if cors_val:
        if cors_val.strip() == "*":
            cors_status = "warning"
            cors_score = 2
            cors_rec = "Access-Control-Allow-Origin is set to '*' (wildcard). This makes the resource accessible to all websites. If this site contains sensitive user data, restrict this to specific origins."
        else:
            cors_status = "good"
            cors_score = 5
            cors_rec = f"Access-Control-Allow-Origin is set to '{cors_val}', restricting requests to trusted origins."

    results["Access-Control-Allow-Origin"] = {
        "value": headers.get("Access-Control-Allow-Origin") or headers.get("access-control-allow-origin"),
        "status": cors_status,
        "score_contribution": cors_score,
        "max_score": 5,
        "beginner_explanation": "This header is used to manage Cross-Origin Resource Sharing (CORS). It tells the browser which outside websites are allowed to request resources and read data from this site.",
        "security_impact": "Prevents unauthorized domains from fetching sensitive data. If set to wildcard '*' on authenticated pages, any site can read data.",
        "real_world_example": "If a banking site has 'Access-Control-Allow-Origin: *', a malicious forum you visit can execute a script in your browser to request your balance details from the bank, and read the response.",
        "recommendation": cors_rec,
        "exam_tip": "CORS issues and Access-Control-Allow-Origin are highly relevant in Cloud/Web security topics. A wildcard '*' value creates a cross-origin vulnerability for authenticated APIs."
    }
    total_score += cors_score

    return {
        "score": total_score,
        "max_score": max_total_score,
        "grade": calculate_grade(total_score),
        "results": results
    }

def calculate_grade(score: int) -> str:
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    else:
        return "F"
