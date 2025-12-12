#!/usr/bin/python3
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
import queue
import ipaddress
import argparse
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings()

class CDNDetector:
    """CDN检测器，包含国内外常见CDN IP段"""
    
    def __init__(self):
        self.cdn_ranges = []
        self.load_cdn_ranges()
    
    def load_cdn_ranges(self):
        """加载常见CDN IP段"""
        # 国内CDN
        china_cdns = [
            # 阿里云CDN
            "47.0.0.0/12", "106.11.0.0/16", "120.24.0.0/14","47.96.0.0/11", "118.31.0.0/16", "47.100.0.0/16",
            # 腾讯云CDN
            "119.28.0.0/16", "129.204.0.0/16", "81.69.0.0/16","123.207.0.0/16", "150.109.0.0/16", "182.254.0.0/16",
            # 网宿CDN
            "113.200.0.0/15", "183.61.0.0/17", "58.216.0.0/15","117.21.0.0/16", "121.12.0.0/15",
            # 蓝汛CDN
            "123.129.0.0/16", "123.203.0.0/16",
            # 金山云CDN
            "116.211.0.0/16", "120.92.0.0/16",
            # 百度云CDN
            '180.76.0.0/16', '220.181.0.0/16', '123.125.0.0/16',
            # 七牛云CDN
            "101.71.0.0/16", "115.231.0.0/16",
            # 又拍云CDN
            "117.34.0.0/16", "122.224.0.0/16",
            # 华为云CDN
            "116.207.0.0/16", "122.112.0.0/18", "121.36.0.0/14",
        ]
        
        # 国外CDN
        global_cdns = [
            # Cloudflare
            "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
            "104.16.0.0/12", "108.162.192.0/18", "131.0.72.0/22",
            "141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13",
            "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20",
            "197.234.240.0/22", "198.41.128.0/17",
            # Akamai
            "23.0.0.0/12", "95.100.0.0/15", "104.64.0.0/10",
            # Fastly
            "23.235.32.0/20", "104.156.80.0/20",
            # AWS CloudFront
            "13.32.0.0/15", "13.35.0.0/16", "52.46.0.0/18",
            "52.84.0.0/15", "54.182.0.0/16", "54.192.0.0/16",
        ]
        
        all_cdns = china_cdns + global_cdns
        self.cdn_ranges = [ipaddress.ip_network(cidr, strict=False) for cidr in all_cdns]
    
    def is_cdn_ip(self, ip):
        """检测IP是否属于CDN"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for cidr in self.cdn_ranges:
                if ip_obj in cidr:
                    return True
            return False
        except ValueError:
            return False

class RealIPScanner:
    """真实IP扫描器"""
    
    def __init__(self, threads=50, timeout=10):
        self.threads = threads
        self.timeout = timeout
        self.cdn_detector = CDNDetector()
        
        # 禁用SSL警告
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except:
            pass

    def resolve_dns(self, domain):
        """DNS解析获取IP"""
        ips = []
        try:
            # 解析A记录
            answers = dns.resolver.resolve(domain, 'A')
            for rdata in answers:
                ips.append(str(rdata))
        except:
            pass
        
        return ips

    def get_ip_by_direct_connect(self, domain):
        """通过直接连接获取IP"""
        try:
            # 使用socket直接连接
            ip = socket.gethostbyname(domain)
            return ip
        except:
            return None

    def get_ip_by_http_requests(self, domain):
        """通过HTTP请求获取真实IP"""
        methods = [
            # 正常请求
            {'headers': {}, 'verify_ssl': True},
            # 修改Host头
            {'headers': {'Host': 'localhost'}, 'verify_ssl': False},
            # 使用X-Forwarded-For
            {'headers': {'X-Forwarded-For': '8.8.8.8'}, 'verify_ssl': False},
            # 使用X-Real-IP
            {'headers': {'X-Real-IP': '8.8.8.8'}, 'verify_ssl': False},
            # 随机User-Agent
            {'headers': {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}, 'verify_ssl': True},
        ]
        
        schemes = ['http', 'https']
        found_ips = set()
        
        for scheme in schemes:
            for method in methods:
                try:
                    url = f"{scheme}://{domain}"
                    response = requests.get(
                        url,
                        headers=method['headers'],
                        timeout=self.timeout,
                        allow_redirects=False,
                        verify=method['verify_ssl']
                    )
                    
                    # 从响应头获取IP信息
                    if 'X-Real-IP' in response.headers:
                        found_ips.add(response.headers['X-Real-IP'])
                    
                    # 获取连接的实际IP
                    if response.raw._connection:
                        if hasattr(response.raw._connection, 'sock'):
                            peer = response.raw._connection.sock.getpeername()
                            if peer:
                                found_ips.add(peer[0])
                    
                except Exception:
                    continue
        
        return list(found_ips)

    def check_domain_history(self, domain):
        """查询域名历史解析记录"""
        historical_ips = set()
        
        # 使用多个公共DNS查询
        dns_servers = [
            '8.8.8.8',      # Google DNS
            '1.1.1.1',      # Cloudflare DNS
            '114.114.114.114', # 114 DNS
            '223.5.5.5',    # 阿里DNS
            '119.29.29.29'  # 腾讯DNS
        ]
        
        for dns_server in dns_servers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                answers = resolver.resolve(domain, 'A')
                for rdata in answers:
                    historical_ips.add(str(rdata))
            except:
                continue
        
        return list(historical_ips)

    def find_real_ip(self, domain):
        """查找域名的真实IP"""
        print(f"[*] 扫描域名: {domain}")
        
        all_ips = set()
        cdn_ips = []
        non_cdn_ips = []
        real_ip = None
        
        try:
            # 方法1: DNS解析
            dns_ips = self.resolve_dns(domain)
            for ip in dns_ips:
                all_ips.add(ip)
            
            # 方法2: 直接连接
            direct_ip = self.get_ip_by_direct_connect(domain)
            if direct_ip:
                all_ips.add(direct_ip)
            
            # 方法3: HTTP请求
            http_ips = self.get_ip_by_http_requests(domain)
            for ip in http_ips:
                all_ips.add(ip)
            
            # 方法4: 历史记录查询
            history_ips = self.check_domain_history(domain)
            for ip in history_ips:
                all_ips.add(ip)
            
            # 分析IP类型
            for ip in all_ips:
                if self.cdn_detector.is_cdn_ip(ip):
                    cdn_ips.append(ip)
                else:
                    non_cdn_ips.append(ip)
            
            # 确定真实IP（优先非CDN IP）
            if non_cdn_ips:
                real_ip = non_cdn_ips[0]  # 选择第一个非CDN IP
                status = "真实IP(绕过CDN)"
            elif all_ips:
                real_ip = list(all_ips)[0]  # 使用第一个找到的IP
                status = "可能IP(可能为CDN)"
            else:
                real_ip = None
                status = "未找到IP"
            
            # 输出结果
            if real_ip:
                if non_cdn_ips:
                    print(f"[+] {domain} -> {real_ip} (绕过CDN成功)")
                else:
                    print(f"[!] {domain} -> {real_ip} (可能仍为CDN)")
            else:
                print(f"[-] {domain} -> 未找到IP")
            
            return {
                'domain': domain,
                'real_ip': real_ip,
                'all_ips': list(all_ips),
                'cdn_ips': cdn_ips,
                'non_cdn_ips': non_cdn_ips,
                'status': status
            }
            
        except Exception as e:
            print(f"[-] 扫描 {domain} 时出错: {e}")
            return {
                'domain': domain,
                'real_ip': None,
                'all_ips': [],
                'cdn_ips': [],
                'non_cdn_ips': [],
                'status': f'错误: {str(e)}'
            }

    def scan_domains(self, domains):
        """批量扫描域名获取真实IP"""
        print(f"[*] 开始批量扫描 {len(domains)} 个域名获取真实IP")
        print(f"[*] 线程数: {self.threads}, 超时: {self.timeout}秒")
        print("[*] CDN绕过技术: DNS多解析 + HTTP特殊请求 + 历史记录查询")
        print("=" * 60)
        
        start_time = time.time()
        results = []
        successful_scans = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_domain = {
                executor.submit(self.find_real_ip, domain): domain 
                for domain in domains
            }
            
            for future in as_completed(future_to_domain):
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result['real_ip']:
                        successful_scans += 1
                        
                except Exception as e:
                    domain = future_to_domain[future]
                    print(f"[-] 处理 {domain} 时发生错误: {e}")
        
        end_time = time.time()
        print("\n" + "=" * 60)
        print("真实IP扫描完成!")
        print(f"总域名数: {len(domains)}")
        print(f"成功找到IP: {successful_scans}")
        print(f"耗时: {end_time - start_time:.2f} 秒")
        
        return results

class PortScanner:
    """端口扫描器"""
    
    def __init__(self):
        self.ports = []
        self.final_url = []
        self.ips = []

    class PortScan(threading.Thread):
        def __init__(self, queue, port_scanner):
            threading.Thread.__init__(self)
            self._queue = queue
            self.port_scanner = port_scanner

        def run(self):
            while not self._queue.empty():
                scan_ip = self._queue.get()
                try:
                    self.port_scanner.mas_port_scan(scan_ip)
                    self.port_scanner.nmap_scan(scan_ip)
                except Exception as e:
                    print(e)
                    pass

    # 调用masscan
    def mas_port_scan(self, scan_ip):
        temp_ports = []  # 设定一个临时端口列表
        os.system('./masscan ' + scan_ip + ' -p 1-65535 -oJ masscan.json --rate 1000')
        # 提取json文件中的端口
        if os.path.exists('masscan.json'):
            with open('masscan.json', 'r') as f:
                for line in f:
                    if line.startswith('{ '):
                        temp = json.loads(line[:-2])
                        temp1 = temp["ports"][0]
                        temp_ports.append(str(temp1["port"]))

            if len(temp_ports) > 50:
                temp_ports.clear()  # 如果端口数量大于50，说明可能存在防火墙，属于误报，清空列表
            else:
                self.ports.extend(temp_ports)  # 小于50则放到总端口列表里

    # 调用nmap识别服务
    def nmap_scan(self, scan_ip):
        nm = nmap.PortScanner()
        try:
            for port in self.ports:
                ret = nm.scan(scan_ip, port, arguments='-sV')
                service_name = ret['scan'][scan_ip]['tcp'][int(port)]['name']
                print('[*] 主机 ' + scan_ip + ' 的 ' + str(port) + ' 端口服务为：' + service_name)
                if 'http' in service_name or service_name == 'sun-answerbook':
                    if service_name == 'https' or service_name == 'https-alt':
                        scan_url_port = 'https://' + scan_ip + ':' + str(port)
                        self.get_title(scan_url_port, service_name)
                    else:
                        scan_url_port = 'http://' + scan_ip + ':' + str(port)
                        self.get_title(scan_url_port, service_name)
                else:
                    with open('result.txt', 'a') as f:
                        f.write(scan_ip + '\t\t' + 'port: ' + str(port) + '\t\t' + service_name + '\n')
        except Exception as e:
            print(e)
            pass

    # 获取网站的web应用程序名和网站标题信息
    def get_title(self, scan_url_port, service_name):
        try:
            r = requests.get(scan_url_port, timeout=3, verify=False)
            # 获取网站的页面编码
            r_detectencode = chardet.detect(r.content)
            actual_encode = r_detectencode['encoding']
            # 在 Python 3 中，r.content 是 bytes，需要解码为字符串
            content = r.content.decode(actual_encode) if actual_encode else r.content.decode('utf-8', errors='ignore')
            response = re.findall(r'<title>(.*?)</title>', content, re.S)
            if not response:
                with open('result.txt', 'a') as f:
                    f.write('[*] Website: ' + scan_url_port + '\t\t' + service_name + '\n')
            else:
                # 在 Python 3 中，标题已经是字符串，直接使用
                res = response[0]
                banner = r.headers.get('server', 'Unknown')
                with open('result.txt', 'a') as f:
                    f.write('[*] Website: ' + scan_url_port + '\t\t' + banner + '\t\t' + 'Title: ' + res + '\n')
        except Exception as e:
            print(e)
            pass

    # 扫描结果去重
    def remove_dup(self):
        if os.path.exists('result.txt'):
            for line in open('result.txt', 'r', encoding='utf-8'):
                if line not in self.final_url:
                    self.final_url.append(line)
                    with open('final_result.txt', 'a', encoding='utf-8') as f:
                        f.write(line)
            time.sleep(1)
            os.remove('result.txt')
            for line in open('final_result.txt', 'r', encoding='utf-8'):
                if 'Website' in line:
                    line = line.strip('\n\r\t').split('\t\t')[0].replace('[*] Website: ', '')
                    with open('url.txt', 'a', encoding='utf-8') as f:
                        f.write(line + '\n')
        else:
            pass

    # 传入ip启用多线程
    def multi_threading_scan(self, ip_list):
        q = queue.Queue()
        for ip in ip_list:
            q.put(ip)
            
        threads = []
        thread_count = min(50, len(ip_list))  # 限制线程数
        
        for i in range(thread_count):
            threads.append(self.PortScan(q, self))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

def load_domains_from_file(file_path):
    """从文件加载域名列表"""
    domains = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                domain = line.strip()
                if domain and not domain.startswith('#'):
                    # 清理域名格式
                    domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
                    domains.append(domain)
        return domains
    except Exception as e:
        print(f"[-] 读取域名文件失败: {e}")
        return []

def save_domain_ip_mapping(results, output_file='domain_ip_mapping.txt'):
    """保存域名和IP的对应关系到文件"""
    with open(output_file, 'w', encoding='utf-8') as f:
        for result in results:
            if result['real_ip']:
                f.write(f"{result['domain']}\t{result['real_ip']}\n")
    
    print(f"[+] 域名-IP对应关系已保存到: {output_file}")

def main():
    parser = argparse.ArgumentParser(description='集成真实IP识别和端口扫描工具')
    parser.add_argument('-d', '--domain', help='单个域名扫描')
    parser.add_argument('-f', '--file', help='域名列表文件路径')
    parser.add_argument('-t', '--threads', type=int, default=20, help='并发线程数 (默认: 20)')
    parser.add_argument('--timeout', type=int, default=10, help='请求超时时间 (默认: 10秒)')
    parser.add_argument('--skip-realip', action='store_true', help='跳过真实IP扫描，直接使用文件中的IP')
    parser.add_argument('--ip-file', help='IP列表文件路径（当使用--skip-realip时）')
    parser.add_argument('--domain-ip-file', default='domain_ip_mapping.txt', 
                       help='域名-IP对应关系输出文件 (默认: domain_ip_mapping.txt)')
    
    args = parser.parse_args()
    
    if not args.domain and not args.file and not args.ip_file:
        print("错误: 请指定要扫描的域名或域名列表文件或IP列表文件")
        print("使用方法:")
        print("  单个域名: python3 masnmapscan.py -d example.com")
        print("  批量域名: python3 masnmapscan.py -f domains.txt")
        print("  跳过真实IP扫描: python3 masnmapscan.py --skip-realip --ip-file ip.txt")
        sys.exit(1)
    
    start_time = datetime.datetime.now()
    
    # 准备扫描目标
    if args.skip_realip and args.ip_file:
        # 直接使用IP文件
        with open(args.ip_file, 'r', encoding='utf-8') as f:
            ip_list = [line.strip() for line in f if line.strip()]
        print(f"[*] 加载 {len(ip_list)} 个IP进行端口扫描")
        results = []  # 没有域名-IP映射结果
    else:
        # 使用域名进行真实IP扫描
        domains = []
        if args.domain:
            domains = [args.domain]
        elif args.file:
            domains = load_domains_from_file(args.file)
            if not domains:
                print("[-] 未找到有效域名，程序退出")
                sys.exit(1)
        
        print(f"[*] 加载 {len(domains)} 个待扫描域名")
        
        # 第一步：真实IP扫描
        real_ip_scanner = RealIPScanner(threads=args.threads, timeout=args.timeout)
        results = real_ip_scanner.scan_domains(domains)
        
        # 保存域名-IP对应关系
        save_domain_ip_mapping(results, args.domain_ip_file)
        
        # 提取真实IP
        ip_list = []
        for result in results:
            if result['real_ip']:
                ip_list.append(result['real_ip'])
        
        # 去重
        ip_list = list(set(ip_list))
        print(f"[*] 获取到 {len(ip_list)} 个真实IP进行端口扫描")
        
        # 保存IP列表
        with open('real_ips.txt', 'w', encoding='utf-8') as f:
            for ip in ip_list:
                f.write(ip + '\n')
        print("[+] 真实IP已保存到 real_ips.txt")
    
    # 第二步：端口扫描
    if ip_list:
        print("\n" + "=" * 60)
        print("[*] 开始端口扫描...")
        port_scanner = PortScanner()
        port_scanner.multi_threading_scan(ip_list)
        port_scanner.remove_dup()
        
        print("[+] 端口扫描完成!")
        if os.path.exists('final_result.txt'):
            print("[+] 扫描结果已保存到 final_result.txt")
        if os.path.exists('url.txt'):
            print("[+] URL列表已保存到 url.txt")
    else:
        print("[-] 没有找到有效的IP进行端口扫描")
    
    spend_time = (datetime.datetime.now() - start_time).seconds
    print('\n[*] 程序总运行时间: ' + str(spend_time) + ' 秒')

if __name__ == '__main__':
    main()
