from django.shortcuts import render, HttpResponse
from utils.utils import *
from apps.basicModel import *


def index(request):
    if request.method == "GET":
        return render(request, "index.html")
    else:
        # 如果是post, 开始处理url 调用basic_sniff
        url = baseurl(request.POST['url'])
        # 判断url合法性
        warn_msg = check_url(url)
        if warn_msg is not None:
            return HttpResponse(warn_msg)
        basic_urls = url_sniff(url=url, root_url=url)

        final_data = {}
        for basic_url in basic_urls:
            print(basic_url)
            [flag, data] = get_flag_data(basic_url)
            try:
                final_data = flag_check(flag, data, url, basic_url, basic_urls, final_data)
            except:
                return HttpResponse("[-] 请检查目标网站状态")
        return render(request, 'result.html', {"final_data": final_data})
