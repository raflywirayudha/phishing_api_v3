import httpx
from urllib.parse import quote

async def check_phishtank(client: httpx.AsyncClient, url: str) -> bool:
    encoded_url = quote(url, safe='')
    endpoint = f"https://phishtankapi.circl.lu/checkurl?url={encoded_url}"
    try:
        resp = await client.get(endpoint)
        if resp.status_code == 200:
            data = resp.json()
            return data.get('in_database', False) and data.get('valid') == 'y'
        return False
    except Exception as e:
        print(f"Error pada PhishTank API: {e}")
        return False