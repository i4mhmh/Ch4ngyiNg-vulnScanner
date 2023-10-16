# -*- coding: utf-8 -*-
"""
"* Author     : M0nk3y"
"* Version    : 3.1"
"""
import urllib.parse
from utils.utils import *
import requests
from bs4 import BeautifulSoup
from apps.fileUpload import file_upload
from apps.fileDownload import get_file_download_payloads
from apps.fileInclusion import get_file_inclusion_payloads
from apps.xxe import get_xxe_payloads
from apps.ssrf import get_ssrf_payloads
from apps.ssti import *

headers = {
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.8',
    'Cache-Control': 'max-age=0',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36',
    'Connection': 'keep-alive',
}


def check_url(url):
    try:
        r = requests.get(url=url, headers=headers, verify=False)
        if r.status_code == 404 or r.status_code == 502:
            return "[-] 网站无法访问"
    except Exception as e:
        return "[-] 请检查url格式[http://xxx.xxx, https://xxx.xxx]", e
    return None


def url_sniff(url, root_url, url_maps=None, flag=1):
    if url_maps is None:
        url_maps = []
    final_list = []
    ignore_suffixes = ['pdf', 'javascript']
    r = requests.get(url=url, headers=headers, verify=False)

    # 判断是否已经拿过该url 或者第二次过滤
    if url not in url_maps or flag == 2:
        for link in BeautifulSoup(r.text, 'html.parser').find_all("a"):
            if len(link.find_all("img")) != 0:
                # 图片链接跳出循环
                continue
            has_ignore = False

            for ignore_suffix in ignore_suffixes:
                if ignore_suffix in str(link):
                    has_ignore = True
                    break

            if has_ignore:
                continue
                # 拿href
            if link.has_attr('href'):
                link_url = link['href']
                # 先判断是否是原地址
                if "#" in link_url or '/' == link_url:
                    continue
                if not link_url.startswith('http') and 'www' not in link_url:
                    link_url = urllib.parse.urljoin(url, link_url)
                # 再判断是否是本网站内的链接
                if not link_url.startswith(root_url):
                    continue
                # 最后所有过滤条件均满足,判断是否在final_list内后直接将其存放在已捕获的列表内
                if link_url not in url_maps and link_url not in final_list:
                    final_list.append(link_url)
        return final_list
    else:
        pass


def get_flag_data(url):
    page_content = requests.get(url=url, headers=headers, verify=False)
    soup = BeautifulSoup(page_content.text, 'html.parser')
    # 首先过滤文件上传, input.type里是必须会有file的, 直接return 发往文件上传模块
    inputs = soup.find_all("input")
    data = {}
    if len(inputs) == 0:
        # 没有发现inputs 过一遍get 如果没有直接pass掉
        flag = -1
        return [flag, data]
    flag = 0

    # 遍历一次 取出input_data  [[ name, type, value ], [ name, type, value ]]
    inputs_data = []
    for my_input in inputs:
        input_data = []
        # 判断是否submit按钮需要传参, 如果没有name 就直接丢掉
        if str(my_input['type']).lower() == 'submit' and my_input.has_key("name") == False:
            continue

        # 判断name, value, type是否存在
        if not my_input.has_key('name'):
            # 有input 但是没有name 直接pass 没办法拿js 太麻烦了
            return [2, data]

        # 没name 不知道怎么去拿了 直接退回不要在form上浪费时间
        input_data.append(my_input["name"])
        input_data.append(my_input["value"]) if my_input.has_key("value") != False else input_data.append("")

        if my_input.has_key("type"):
            input_data.append(my_input["type"])
            if my_input['type'] == 'file':
                flag = 1
        inputs_data.append(input_data)

    # 判断是否存在select框, 如果有直接append name None
    selects = soup.find_all("select")
    if selects:
        for select in selects:
            select_data = []
            if "name" in select.attrs:
                select_data.append(select['name'])
                select_data.append("")
                select_data.append("")
                inputs_data.append(select_data)
            else:
                continue
    textareas = soup.find_all("textarea")
    for textarea in textareas:
        if textarea:
            if 'name' not in textarea.attrs:
                continue
            if 'value' not in textarea.attrs:
                textarea['value'] = ''
            textarea_list = [textarea['name'], textarea['value'], ""]
            inputs_data.append(textarea_list)
    form = soup.find("form")
    form_data = get_form(form=form, url=url)
    data.update(form_data)
    data["input_data"] = inputs_data
    # 拿提交方式|提交url|inputs
    return [flag, data]


# 获取form内所有元素
def get_form(form, url):
    # 判断是否有form / 应该是有的 否则js传参识别复杂度太大
    if form.has_attr("method"):
        form_method = form['method']
    else:
        form_method = 'get'

    # 获取action
    if form.has_attr("action"):
        action = form['action']
        form_action = form['action']
        form_action = urllib.parse.urljoin(url, form_action)
    else:
        form_action = url
        # 这里拼接url
    data = {'action': form_action, "method": form_method}
    return data


# flag 判断
def flag_check(flag, data, root_url, basic_url, basic_urls, final_data):
    if flag == 1:
        data['file_upload'] = 1
        data['urls'] = basic_urls
        res = range_attack(data=data)
        if res is not None:
            final_data = merge(res, final_data)

    # 没有form的情况 这里如果没有form 需要再次考虑是否包含二层url, 需要再次过滤, 不考虑二次过滤后还有form的情况
    elif flag == -1:
        again_urls = []
        # 先检查是否为form 传参
        if "?" in basic_url:
            params = params_get(url=basic_url)
            if params is not None:
                res = range_attack(data=params)
                if res is not None:
                    final_data = merge(res, final_data)
        else:
            again_urls = url_sniff(url=basic_url, root_url=root_url, url_maps=basic_urls, flag=2)
        for again_url in again_urls:
            [flag, data] = get_flag_data(url=again_url)
            if flag == 1:
                data['file_upload'] = 1
                data['urls'] = basic_urls
                res = range_attack(data=data)
                if res is not None:
                    final_data = merge(res, final_data)
            elif flag == -1:
                # 不再做嵌套了 也不用在写函数专门用来封装
                # 过滤一次url参数, 如果存在url参数 -> 挨个试一下 否则continue
                if "?" in again_url:
                    params = params_get(url=again_url)
                    if params is not None:
                        res = range_attack(data=params)
                        if res is not None:
                            final_data = merge(res, final_data)
                else:
                    # 如果没有url传参 也没有form 直接pass掉
                    continue
            elif flag == 2:
                # flag2 直接跳过
                # final_data[again_url] =
                pass
            else:
                # form 传参
                res = range_attack(data=data)
                if res is not None:
                    final_data = merge(res, final_data)
        # xxe()
    elif flag == 2:
        # flag2 直接跳过
        pass

    # 不用文件传 |XXE|file_download|file_inclusion|SSRF|SSTI
    else:
        res = range_attack(data=data)
        if res is not None:
            final_data = merge(res, final_data)
    return final_data


def range_attack(data, attack_list=None):
    if attack_list is None:
        attack_list = []

    if 'file_upload' in data:
        result = file_upload(data)
        if result is not None:
            return result
    else:
        attack_list = ["xxe", "file_download", "ssrf", "file_inclusion", "ssti"]
        for attack in attack_list:
            if "ssti" is attack:
                result = ssti_attack(data=data)
            else:
                result = attack_model(model=attack, data=data)
            if result is not None:
                return result


# 遍历攻击
def attack_model(model, data):
    final_data = {}
    if model == "file_upload":
        return file_upload(data=data)
    else:
        attack_payloads = eval("get_" + model + '_payloads()')
        # 针对xxe , ssrf, file_inclusion, file_download, SSTI这五种, 统一都可以按一种格式来测试
        if 'url' in data:
            url = data['url'] + '?'
            params = data['params']

            origin_params = params
            for key in params:
                for payload in attack_payloads:
                    # 判断传的是几个参数, 一个直接赋值 多个需要加&
                    if len(params) == 1:
                        url += key + "=" + payload
                    else:
                        params[key] = payload
                        for k, v in params:
                            param_data = k + "=" + v + "&"
                            url += param_data
                        url = url[:-1]  # 删除最后一个&
                    # 有可能会报错 所有TODO: 拼接的时候需要判断一下
                    try:
                        r = requests.get(url=url, headers=headers, hooks={"response": print_roundtrip})

                    except:
                        continue

                    if check_result(r):
                        # 任意文件下载中也会包含其他模块关键字，这里需要排除
                        if model == "file_download" and not any(
                                k in r.headers.get("Content-Type") for k in ['application/octet-stream', 'attachment']):
                            pass
                        else:
                            final_data[url] = [model, r.result]
                            return final_data
                    else:
                        pass

                url = data['url'] + '?'
                params = origin_params

        # form
        else:
            url = data['action']
            inputs = data['input_data']
            form_data = {}
            for my_input in inputs:
                if my_input[1]:
                    form_data[my_input[0]] = my_input[1]

                else:
                    form_data[my_input[0]] = ""
            for payload in attack_payloads:
                # if model == 'xxe':
                #     payload = payload.encode('utf-16')
                #     payload = urllib.parse.quote(payload, 'utf-8')
                for my_input in inputs:
                    if my_input[1] == "":
                        form_data[my_input[0]] = payload
                r = requests.post(url=url, headers=headers, data=form_data, verify=False,
                                  hooks={"response": print_roundtrip})
                if check_result(r):
                    if model == "file_download" and not any(
                            k in r.headers.get("Content-Type") for k in ['application/octet-stream', 'attachment']):
                        pass
                    else:
                        final_data[url] = [model, r.result.replace(r"\r\n", "<br>")]
                        return final_data
                r = requests.get(url=url, headers=headers, data=form_data, verify=False,
                                 hooks={"response": print_roundtrip})
                if check_result(r):
                    if model == "file_download" and not any(
                            k in r.headers.get("Content-Type") for k in ['application/octet-stream', 'attachment']):
                        pass
                    else:
                        final_data[url] = [model, r.result]
                        return final_data
