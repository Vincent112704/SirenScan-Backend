from bs4 import BeautifulSoup
from urllib.parse import urlparse


def parse_html_content(html_content):
    """Extract all unique HTTP/HTTPS URLs from anchor tags in HTML content."""
    soup = BeautifulSoup(html_content, 'html.parser')
    urls = []
    seen = set()
    for tag in soup.find_all('a', href=True):
        href = tag['href'].strip()
        if href and href not in seen and urlparse(href).scheme in ('http', 'https'):
            urls.append(href)
            seen.add(href)
    return urls
    
