#!/usr/bin/python
# coding: utf-8


import nmap
import datetime
import time
import threading
import requests
import chardet
import re
import json
import os
import sys
import socket
import Queue

requests.packages.urllib3.disable_warnings()

reload(sys)
sys.setdefaultencoding('utf-8')

ports = []
final_url = []
ips = []


class PortScan(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self._queue = queue

    def run(self):
        while not self._queue.empty():
            scan_ip = self._queue.get()
            try:
                Masportscan(scan_ip)
                Nmapscan(scan_ip)
            except Exception as e:
                print e
                pass


# 调用masscan
def Masportscan(scan_ip):
    temp_ports = []  # 设定一个临时端口列表
    os.system('../masscan/bin/masscan ' + scan_ip + ' -p 1-65535 -oJ masscan.json --rate 1000')
    # 提取json文件中的端口
    with open('masscan.json', 'r') as f:
        for line in f:
            if line.startswith('{ '):
                temp = json.loads(line[:-2])
                temp1 = temp["ports"][0]
                temp_ports.append(str(temp1["port"]))

    if len(temp_ports) > 50:
        temp_ports.clear()  # 如果端口数量大于50，说明可能存在防火墙，属于误报，清空列表
    else:
        ports.extend(temp_ports)  # 小于50则放到总端口列表里


# 调用nmap识别服务
def Nmapscan(scan_ip):
    nm = nmap.PortScanner()
    try:
        for port in ports:
            ret = nm.scan(scan_ip, port, arguments='-sV')
            service_name = ret['scan'][scan_ip]['tcp'][int(port)]['name']
            print '[*] 主机 ' + scan_ip + ' 的 ' + str(port) + ' 端口服务为：' + service_name
            if 'http' in service_name or service_name == 'sun-answerbook':
                if service_name == 'https' or service_name == 'https-alt':
                    scan_url_port = 'https://' + scan_ip + ':' + str(port)
                    Title(scan_url_port, service_name)
                else:
                    scan_url_port = 'http://' + scan_ip + ':' + str(port)
                    Title(scan_url_port, service_name)
            else:
                with open('result.txt', 'ab+') as f:
                    f.writelines(scan_ip + '\t\t' + 'port: ' + str(port) + '\t\t' + service_name + '\n')
    except Exception as e:
        print e
        pass


# 获取网站的web应用程序名和网站标题信息
def Title(scan_url_port, service_name):
    try:
        r = requests.get(scan_url_port, timeout=3, verify=False)
        # 获取网站的页面编码
        r_detectencode = chardet.detect(r.content)
        actual_encode = r_detectencode['encoding']
        response = re.findall(u'<title>(.*?)</title>', r.content, re.S)
        if response == []:
            with open('result.txt', 'ab+') as f:
                f.writelines('[*] Website: ' + scan_url_port + '\t\t' + service_name + '\n')
        else:
            # 将页面解码为utf-8，获取中文标题
            res = response[0].decode(actual_encode).decode('utf-8').encode('utf-8')
            banner = r.headers['server']
            with open('result.txt', 'ab+') as f:
                f.writelines('[*] Website: ' + scan_url_port + '\t\t' + banner + '\t\t' + 'Title: ' + res + '\n')
    except Exception as e:
        print e
        pass


# 扫描结果去重
def Removedup():
    if os.path.exists('result.txt'):
        for line in open('result.txt', 'r'):
            if line not in final_url:
                final_url.append(line)
                with open('final_result.txt', 'ab+') as f:
                    f.writelines(line)
        time.sleep(1)
        os.remove('result.txt')
        for line in open('final_result.txt', 'r'):
            if 'Website' in line:
                line = line.strip('\n\r\t').split('\t\t')[0].replace('[*] Website: ', '')
                with open('url.txt', 'ab+') as f:
                    f.writelines(line+'\n')
    else:
        pass


# 获取子域名对应ip
def Get_domain_ip(sub):
    f = open(sub, 'r')
    for line in f.readlines():
        try:
            if 'www.' in line:
                extract_line = line.replace('www.', '')
                print line.strip('\n\r\t'), socket.gethostbyname(extract_line.strip('\n\r\t'))
                with open('subdomain-ip.txt', 'ab+') as l:
                    l.writelines(line.strip('\n\r\t') + '\t\t' + socket.gethostbyname(extract_line.strip('\n\r\t')) + '\n')
            else:
                print line.strip('\n\r\t'), socket.gethostbyname(line.strip('\n\r\t'))
                with open('subdomain-ip.txt', 'ab+') as l:
                    l.writelines(line.strip('\n\r\t') + '\t\t' + socket.gethostbyname(line.strip('\n\r\t')) + '\n')
        except Exception, e:
            print e
            pass
    time.sleep(1)
    # 对子域名解析的ip进行去重
    ip_temps = []
    l = open(r'subdomain-ip.txt', 'r')
    for line in l.readlines():
        line = line.strip('\n\t\r').split('\t\t')[-1]
        ips.append(line)
    for ip_temp in ips:
        if ip_temp not in ip_temps:
            ip_temps.append(ip_temp)
    for ip in ip_temps:
        with open('ip.txt', 'ab+') as f:
            f.writelines(ip + '\n')
    f.close()
    l.close()
    time.sleep(1)


# 传入ip启用多线程
def Multithreading():
    queue = Queue.Queue()
    f = open(r'ip.txt', 'r')
    for line in f.readlines():
        final_ip = line.strip('\n')
        queue.put(final_ip)
    threads = []
    thread_count = 200
    for i in range(thread_count):
        threads.append(PortScan(queue))
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    f.close()


# 判断扫描文件是否存在，存在则直接扫描，不存在则调用域名解析
def main(sub):
    try:
        if os.path.exists('ip.txt'):
            Multithreading()
        else:
            Get_domain_ip(sub)
            Multithreading()
    except Exception as e:
        print e
        pass


if __name__ == '__main__':
    start_time = datetime.datetime.now()
    if len(sys.argv) < 2:
        print "Usage: python "+sys.argv[0]+u" 子域名文件"
        sys.exit(1)
    else:
        sub = sys.argv[1]
        main(sub)
        Removedup()
    spend_time = (datetime.datetime.now() - start_time).seconds
    print 'The program is running: ' + str(spend_time) + ' second'
