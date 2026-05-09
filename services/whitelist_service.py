import httpx

tranco_cache = {}

async def check_tranco(client: httpx.AsyncClient, domain: str) -> bool:
    if domain in tranco_cache:
        return tranco_cache[domain]
        
    endpoint = f"https://tranco-list.eu/api/ranks/domain/{domain}"
    try:
        resp = await client.get(endpoint)
        if resp.status_code == 200:
            is_safe = len(resp.json().get("ranks", [])) > 0
            tranco_cache[domain] = is_safe
            return is_safe
        return False
    except Exception:
        return False