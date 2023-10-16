"""
"* Author     : M0nk3y"
"* Version    : 1.0"
"""

from urllib.parse import urlparse
from urllib import parse
import textwrap
from bs4 import BeautifulSoup


def baseurl(url):
    try:
        data = parse.urlparse(url).scheme + "://" + parse.urlparse(url).netloc
    except Exception as e:
        return False
    return data

def params_get(url):
    final_data = {}
    if "?" in url:
        url = urlparse(url=url)
        data = parse.parse_qs(url.query)
        final_data['url'] = url.scheme + "://" + url.netloc + url.path
        final_data['params'] = data
        return final_data
    else:
        return None

def merge(dict1, dict2):
    dict2.update(dict1)
    return dict2

# 检查结果
def check_result(r):
    res_list = ["daemon", "M0nk3y is here", "Copyright", "operating"]
    if any(res in r.text for res in res_list):
        return True
    else:
        return False

# 打印payload
def print_roundtrip(response, *args, **kwargs):
    format_headers = lambda d: '\n'.join(f'{k}: {v}' for k, v in d.items())
    response.result = textwrap.dedent('''
        ---------------- request ----------------
        {req.method} {req.url}
        {reqhdrs}
        
        {req.body}
    ''').format(
        req=response.request,
        # res=response,
        reqhdrs=format_headers(response.request.headers),
        # reshdrs=format_headers(response.headers),
    )
