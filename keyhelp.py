import requests
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
from urllib.parse import urljoin

class KeyHelpAPI:
    def __init__(self, base_url: str, api_key: str):
        """Initialize KeyHelp API client.
        
        Args:
            base_url: Base URL of KeyHelp instance (e.g. https://keyhelp.example.com)
            api_key: API key for authentication
        """
        self.base_url = urljoin(base_url.rstrip('/') + '/', 'api/v2/')
        self.session = requests.Session()
        self.session.headers.update({
            'X-API-Key': api_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })

    def _request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict:
        """Send request to API endpoint."""
        url = urljoin(self.base_url, endpoint.lstrip('/'))
        response = self.session.request(method, url, json=data)
        response.raise_for_status()
        return response.json() if response.content else {}

    # Server endpoints
    def get_server_info(self) -> Dict:
        """Get server information."""
        return self._request('GET', '/server')

    def ping(self) -> Dict:
        """Test API connectivity."""
        return self._request('GET', '/ping')

    # Login endpoints
    def get_login_url(self, id_or_name: Union[int, str]) -> Dict:
        """Generate login URL for user."""
        return self._request('GET', f'/login/{id_or_name}')

    # Admin endpoints
    def list_admins(self) -> List[Dict]:
        """List all admin accounts."""
        return self._request('GET', '/admins')

    def create_admin(self, data: Dict) -> Dict:
        """Create new admin account."""
        return self._request('POST', '/admins', data)

    def get_admin(self, id_or_name: Union[int, str]) -> Dict:
        """Get admin account details."""
        endpoint = f'/admins/name/{id_or_name}' if isinstance(id_or_name, str) else f'/admins/{id_or_name}'
        return self._request('GET', endpoint)

    def update_admin(self, id_or_name: Union[int, str], data: Dict) -> Dict:
        """Update admin account."""
        endpoint = f'/admins/name/{id_or_name}' if isinstance(id_or_name, str) else f'/admins/{id_or_name}'
        return self._request('PUT', endpoint, data)

    def delete_admin(self, id_or_name: Union[int, str]) -> None:
        """Delete admin account."""
        endpoint = f'/admins/name/{id_or_name}' if isinstance(id_or_name, str) else f'/admins/{id_or_name}'
        self._request('DELETE', endpoint)

    # Client endpoints
    def list_clients(self) -> List[Dict]:
        """List all client accounts."""
        return self._request('GET', '/clients')

    def create_client(self, data: Dict) -> Dict:
        """Create new client account."""
        return self._request('POST', '/clients', data)

    def get_client(self, id_or_name: Union[int, str]) -> Dict:
        """Get client account details."""
        endpoint = f'/clients/name/{id_or_name}' if isinstance(id_or_name, str) else f'/clients/{id_or_name}'
        return self._request('GET', endpoint)

    def get_client_resources(self, id_or_name: Union[int, str]) -> Dict:
        """Get client resources."""
        endpoint = f'/clients/{id_or_name}/resources'
        return self._request('GET', endpoint)

    def get_client_stats(self, id_or_name: Union[int, str]) -> Dict:
        """Get client statistics."""
        endpoint = f'/clients/{id_or_name}/stats'
        return self._request('GET', endpoint)

    def get_client_traffic(self, id_or_name: Union[int, str]) -> Dict:
        """Get client traffic statistics."""
        endpoint = f'/clients/{id_or_name}/traffic'
        return self._request('GET', endpoint)

    # Domain endpoints
    def list_domains(self) -> List[Dict]:
        """List all domains."""
        return self._request('GET', '/domains')

    def create_domain(self, data: Dict) -> Dict:
        """Create new domain."""
        return self._request('POST', '/domains', data)

    def get_domain(self, id_or_name: Union[int, str]) -> Dict:
        """Get domain details."""
        endpoint = f'/domains/name/{id_or_name}' if isinstance(id_or_name, str) else f'/domains/{id_or_name}'
        return self._request('GET', endpoint)

    def update_domain(self, id_or_name: Union[int, str], data: Dict) -> Dict:
        """Update domain."""
        endpoint = f'/domains/name/{id_or_name}' if isinstance(id_or_name, str) else f'/domains/{id_or_name}'
        return self._request('PUT', endpoint, data)

    def delete_domain(self, id_or_name: Union[int, str]) -> None:
        """Delete domain."""
        endpoint = f'/domains/name/{id_or_name}' if isinstance(id_or_name, str) else f'/domains/{id_or_name}'
        self._request('DELETE', endpoint)

    # DNS endpoints
    def get_dns_records(self, id_or_name: Union[int, str]) -> List[Dict]:
        """Get DNS records for domain."""
        endpoint = f'/dns/name/{id_or_name}' if isinstance(id_or_name, str) else f'/dns/{id_or_name}'
        return self._request('GET', endpoint)

    def update_dns_records(self, id_or_name: Union[int, str], data: Dict) -> Dict:
        """Update DNS records for domain."""
        endpoint = f'/dns/name/{id_or_name}' if isinstance(id_or_name, str) else f'/dns/{id_or_name}'
        return self._request('PUT', endpoint, data)

    def delete_dns_records(self, id_or_name: Union[int, str]) -> None:
        """Delete custom DNS settings for domain."""
        endpoint = f'/dns/name/{id_or_name}' if isinstance(id_or_name, str) else f'/dns/{id_or_name}'
        self._request('DELETE', endpoint)

    # Certificate endpoints
    def list_certificates(self) -> List[Dict]:
        """List all SSL certificates."""
        return self._request('GET', '/certificates')

    def create_certificate(self, data: Dict) -> Dict:
        """Create new SSL certificate."""
        return self._request('POST', '/certificates', data)

    def get_certificate(self, id_or_name: Union[int, str]) -> Dict:
        """Get SSL certificate details."""
        endpoint = f'/certificates/name/{id_or_name}' if isinstance(id_or_name, str) else f'/certificates/{id_or_name}'
        return self._request('GET', endpoint)

    # Database endpoints
    def list_databases(self) -> List[Dict]:
        """List all databases."""
        return self._request('GET', '/databases')

    def create_database(self, data: Dict) -> Dict:
        """Create new database and user."""
        return self._request('POST', '/databases', data)

    def get_database(self, id_or_name: Union[int, str]) -> Dict:
        """Get database details."""
        endpoint = f'/databases/name/{id_or_name}' if isinstance(id_or_name, str) else f'/databases/{id_or_name}'
        return self._request('GET', endpoint)

    # FTP endpoints
    def list_ftp_users(self) -> List[Dict]:
        """List all FTP users."""
        return self._request('GET', '/ftp-users')

    def create_ftp_user(self, data: Dict) -> Dict:
        """Create new FTP user."""
        return self._request('POST', '/ftp-users', data)

    def get_ftp_user(self, id_or_name: Union[int, str]) -> Dict:
        """Get FTP user details."""
        endpoint = f'/ftp-users/name/{id_or_name}' if isinstance(id_or_name, str) else f'/ftp-users/{id_or_name}'
        return self._request('GET', endpoint)