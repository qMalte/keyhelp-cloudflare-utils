import requests
import json
from typing import Optional, Dict, Any

class CloudflareAPI:
    def __init__(self, api_token: str):
        self.base_url = "https://api.cloudflare.com/client/v4"
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }

    def make_request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{endpoint}"
        
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=self.headers,
                json=data
            )
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Fehler bei API-Anfrage: {str(e)}")

    def get_zones(self) -> Dict[str, Any]:
        """Liste aller Zones abrufen"""
        return self.make_request("GET", "/zones?per_page=50")
    
    def purge_cache(self, zone_id: str, files: list) -> Dict[str, Any]:
        """Cache für bestimmte URLs löschen"""
        data = {"files": files}
        return self.make_request("POST", f"/zones/{zone_id}/purge_cache", data)
    
    def add_dns_record(self, zone_id: str, record_type: str, name: str, content: str) -> Dict[str, Any]:
        """DNS-Eintrag hinzufügen"""
        data = {
            "type": record_type,
            "name": name,
            "content": content,
            "proxied": False,
            "priority": 10
        }
        return self.make_request("POST", f"/zones/{zone_id}/dns_records", data)

    def get_dns_records(self, zone_id: str) -> Dict[str, Any]:
        return self.make_request("GET", f"/zones/{zone_id}/dns_records")

    def delete_dns_record(self, zone_id: str, record_id: str) -> Dict[str, Any]:
        return self.make_request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")