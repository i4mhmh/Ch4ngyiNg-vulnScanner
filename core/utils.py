import textwrap
from urllib.parse import urlparse
from urllib import parse
def print_roundtrip(response, *args, **kwargs):
    format_headers = lambda d: '\n'.join(f'{k}: {v}' for k, v in d.items())
    response.result = textwrap.dedent('''
        ---------------- request ----------------
        {req.method} {req.url}
        {reqhdrs}

        {req.body}
        -------------- end request --------------
    ''').format(
        req=response.request, 
        reqhdrs=format_headers(response.request.headers), 
    )

