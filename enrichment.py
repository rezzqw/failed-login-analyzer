import requests

def ip_lookup(ip, key):
    params = {"ipAddress": ip, "maxAgeInDays" : 365}
    headers = {"Key": key, "Accept": "application/json"}
    try:
        response = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=10)

    except requests.RequestException as error:
        print(f"lookup failed: {error.__class__.__name__}")
    else:
        if response.status_code == 200:
            reply = response.json()
            score = reply["data"]["abuseConfidenceScore"]
            country_code = reply["data"]["countryCode"]
            isp = reply["data"]["isp"]
            return (score, country_code, isp)
        
        elif response.status_code == 429:
            return "rate limited, retry later"
        else:
            return "lookup failed: HTTP" + response.status_code