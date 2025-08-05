import requests
from typing import Dict, Any
import asyncio
import aiohttp
REQUEST_TIMEOUT = 3


async def _make_request_async(method: str, url: str, **kwargs) -> Dict[str, Any]:
    try:
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.request(method, url, **kwargs) as response:
                try:
                    data = await response.json()
                except Exception:
                    data = await response.text()
                if response.status == 200 or response.status == 207:
                    return {
                        'success': True,
                        'data': data,
                        'status_code': response.status
                    }
                else:
                    return {
                        'success': False,
                        'error': f"HTTP {response.status}: {data}",
                        'status_code': response.status
                    }
    except asyncio.TimeoutError:
        return {'success': False, 'error': 'Request timeout'}
    except aiohttp.ClientConnectionError:
        return {'success': False, 'error': 'Connection failed'}
    except Exception as e:
        return {'success': False, 'error': f"Request failed: {str(e)}"}

def _make_request(method: str, url: str, **kwargs) -> Dict[str, Any]:
    """
    Make HTTP request with error handling

    Args:
        method: HTTP method (GET, POST, DELETE, etc.)
        url: URL to send the request to
        **kwargs: Additional parameters for requests.request()
        
    Returns:
        Dict containing response data or error info
    """
    try:
        
        response = requests.request(method, url, timeout=REQUEST_TIMEOUT, **kwargs)
        
        if response.status_code == 200:
            return {
                'success': True,
                'data': response.json(),
                'status_code': response.status_code
            }
        elif response.status_code == 207:
            return {
                'success': True,
                'data': response.json(),
                'status_code': response.status_code
            }
        else:
            return {
                'success': False,
                'error': f"HTTP {response.status_code}: {response.text}",
                'status_code': response.status_code
            }
            
    except requests.exceptions.Timeout:
        return {'success': False, 'error': 'Request timeout'}
    except requests.exceptions.ConnectionError:
        return {'success': False, 'error': 'Connection failed'}
    except Exception as e:
        return {'success': False, 'error': f"Request failed: {str(e)}"}
