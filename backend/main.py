import requests
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from analyzer import normalize_url, analyze_headers, USER_AGENT

app = FastAPI(
    title="Security Header Analyzer API",
    description="Educational API for analyzing security headers of web applications for CompTIA Security+ SY0-701.",
    version="1.0.0"
)

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/analyze")
def analyze_site(url: str = Query(..., description="The URL of the website to analyze")):
    try:
        # Validate and normalize the URL
        normalized_url = normalize_url(url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        headers = {
            "User-Agent": USER_AGENT
        }
        # Perform the GET request, following redirects, with an 8-second timeout
        response = requests.get(
            normalized_url, 
            headers=headers, 
            allow_redirects=True, 
            timeout=8
        )
        
        # Analyze the headers from the final response
        analysis_report = analyze_headers(response.headers)
        
        # Add basic scan details to the response
        analysis_report["scan_details"] = {
            "target_url": url,
            "final_url": response.url,
            "status_code": response.status_code,
            "server": response.headers.get("Server", "Unknown")
        }
        
        return analysis_report

    except requests.exceptions.Timeout:
        raise HTTPException(
            status_code=504, 
            detail="Connection timed out. The website took longer than 8 seconds to respond."
        )
    except requests.exceptions.ConnectionError:
        raise HTTPException(
            status_code=502, 
            detail="Failed to connect to the target website. Check the URL domain spelling or server availability."
        )
    except requests.exceptions.RequestException as e:
        raise HTTPException(
            status_code=500, 
            detail=f"An error occurred while fetching headers: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"An unexpected error occurred: {str(e)}"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
