import base64
import httpx
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class ScanRequest(BaseModel):
    url: str

# 🔑 PASTE YOUR VIRUSTOTAL API KEY HERE
VT_API_KEY = "7f2e3ebd04765c4f25b938c6e5b6e6fe89eca2e04a43a30d68555c3068ac4151"

@app.post("/api/v1/scan")
async def scan_url(request: ScanRequest):
    url_lower = request.url.lower()
    print(f"--- INCOMING LIVE THREAT SCAN: {url_lower} ---")
    
    # 🛡️ VirusTotal v3 API requires the URL to be base64 URL-safe encoded without trailing '=' padding
    encoded_url = base64.urlsafe_b64encode(request.url.encode()).decode().strip("=")
    
    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json"
    }
    
    async with httpx.AsyncClient() as client:
        try:
            # Query VirusTotal's global database for this specific URL
            response = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{encoded_url}", 
                headers=headers
            )
            
            if response.status_code == 200:
                result = response.json()
                stats = result["data"]["attributes"]["last_analysis_stats"]
                
                malicious_engines = stats.get("malicious", 0)
                suspicious_engines = stats.get("suspicious", 0)
                harmless_engines = stats.get("harmless", 0)
                undetected_engines = stats.get("undetected", 0)
                
                total_engines = malicious_engines + suspicious_engines + harmless_engines + undetected_engines
                print(f"VT Detection Stats -> Malicious: {malicious_engines}, Suspicious: {suspicious_engines}")

                # Calculate a mathematical risk metric index out of 100
                if total_engines > 0:
                    risk_score = int((malicious_engines / total_engines) * 100)
                else:
                    risk_score = 0
                
                # Determine final verdict based on industry vendor consensus
                if malicious_engines >= 3:
                    verdict = "Malicious"
                elif malicious_engines > 0 or suspicious_engines > 1:
                    verdict = "Suspicious"
                else:
                    verdict = "Safe"
                    
                return {
                    "url": request.url,
                    "risk_score": max(risk_score, 95 if verdict == "Malicious" else (45 if verdict == "Suspicious" else 5)),
                    "verdict": verdict
                }
                
            elif response.status_code == 404:
                # The URL is completely brand new and has never been seen by VirusTotal before
                print("URL not found in database. Treating with caution.")
                return {"url": request.url, "risk_score": 35, "verdict": "Suspicious"}
                
            else:
                print(f"VirusTotal API Error: {response.status_code}")
                return {"url": request.url, "risk_score": 0, "verdict": "Error"}
                
        except Exception as e:
            print(f"Internal Network Connection Error: {str(e)}")
            return {"url": request.url, "risk_score": 0, "verdict": "Error"}
