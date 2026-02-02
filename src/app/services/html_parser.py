from bs4 import BeautifulSoup


def parse_html_content(html_content): 
    soup = BeautifulSoup(html_content, 'html.parser')
    tag = soup.find('a')

    url = tag.get('href') if tag else None
    return url if url else None
    
