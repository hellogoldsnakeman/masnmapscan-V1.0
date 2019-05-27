#!/usr/bin/python
# coding=utf-8


import nmap
import datetime
import threading
import requests
import chardet
import re
import json
import os
requests.packages.urllib3.disable_warnings()
import Queue



final_domains = []
ports = []

class PortScan(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self._queue = queue

    def run(self):
        while not self._queue.empty():
            scan_ip = self._queue.get()
            try:
                portscan(scan_ip)
                Scan(scan_ip)
            except Exception as e:
                print e
                pass

#调用masscan
def portscan(scan_ip):
    temp_ports = [] #设定一个临时端口列表
    os.system('masscan/bin/masscan ' + scan_ip + ' -p 1-65535 -oJ masscan.json --rate 2000')
    #提取json文件中的端口
    with open('masscan.json', 'r') as f:
        for line in f:
            if line.startswith('{ '):
                temp = json.loads(line[:-2])
                temp1 = temp["ports"][0]
                temp_ports.append(str(temp1["port"]))

    if len(temp_ports) > 50:
        temp_ports.clear()       #如果端口数量大于50，说明可能存在防火墙，属于误报，清空列表
    else:
        ports.extend(temp_ports) #小于50则放到总端口列表里


#获取网站的web应用程序名和网站标题信息
def Title(scan_url_port,service_name):
    try:
        r = requests.get(scan_url_port,timeout=3,verify=False)
        #获取网站的页面编码
        r_detectencode = chardet.detect(r.content)
        actual_encode = r_detectencode['encoding']
        response = re.findall(u'<title>(.*?)</title>',r.content,re.S)
        if response == []:
            final_domains.append(scan_url_port + '\t' + service_name)
        else:
            #将页面解码为utf-8，获取中文标题
            res = response[0].decode(actual_encode).decode('utf-8')
            banner = r.headers['server']
            final_domains.append(scan_url_port + '\t' + banner + '\t' + res)     
    except Exception as e:
        print e
        pass

#调用nmap识别服务
def Scan(scan_ip):
    nm = nmap.PortScanner()
    try:
        for port in ports:
            ret = nm.scan(scan_ip,port,arguments='-Pn,-sS')
            service_name = ret['scan'][scan_ip]['tcp'][int(port)]['name']
            print '[*]主机 ' + scan_ip + ' 的 ' + str(port) + ' 端口服务为：' + service_name
            if 'http' in service_name  or service_name == 'sun-answerbook':
                if service_name == 'https' or service_name == 'https-alt':
                    scan_url_port = 'https://' + scan_ip + ':' + str(port)
                    Title(scan_url_port,service_name)
                else:
                    scan_url_port = 'http://' + scan_ip + ':' + str(port)
                    Title(scan_url_port,service_name)
            else:
                final_domains.append(scan_ip+':'+str(port)+'\t'+service_name)
    except Exception as e:
       print e
       pass

#启用多线程扫描
def main():
    queue = Queue.Queue()
    try:
        f = open(r'ip.txt', 'rb')
        for line in f.readlines():
            final_ip = line.strip('\n')
            queue.put(final_ip)
        threads = []
        thread_count = 100
        for i in range(thread_count):
            threads.append(PortScan(queue))
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        f.close()
    except Exception as e:
        print e
        pass


if __name__ =='__main__':
    start_time = datetime.datetime.now()
    main()
    tmp_domians = []
    for tmp_domain in final_domains:
        if tmp_domain not in tmp_domians:
            tmp_domians.append(tmp_domain)
    for url in tmp_domians:
        with open(r'scan_url_port.txt', 'ab+') as ff:
            ff.write(url+'\n')
    spend_time = (datetime.datetime.now() - start_time).seconds
    print '程序共运行了： ' + str(spend_time) + '秒'
