#!/usr/bin/env python3


import random
import subprocess
import json
import sys
import os
import re
import time
import ipaddress
import socket
import dns.resolver
import argparse
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, urlunparse
import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup
import warnings
import urllib3

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# 全局配置
CONFIG = {
    'target_file': 'targets.txt',        # 目标文件
    'real_ips_file': 'real_ips.txt',     # 真实IP地址文件
    'web_urls_file': 'web_urls.txt',     # Web地址文件
    'domain_ip_file': 'domain_ip_map.txt', # 域名与IP对应关系文件
    'summary_file': 'scan_summary.txt',  # 扫描汇总报告文件
    'masscan_output': 'masscan.json',    # masscan结果文件
    'nmap_output': 'nmap.xml',           # nmap结果文件
    'threads': 20,                       # 线程数
    'timeout': 10,                       # 超时时间
    'skip_port_threshold': 100,          # 跳过端口阈值
}

# 域名过滤规则 - 排除明显无效或动态生成的子域名
DOMAIN_FILTER_PATTERNS = [
    # UUID格式
    r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
    # 长数字段域名
    r'a-z0-9]+(\.[a-z0-9]+){2,}\.\d+\.(com|net|cn|org|info|biz|cc|tv)$',
    # 匹配以长随机字母开头，中间有数字的字符串
    r'^[a-z]{8,}\d+[a-z]*\.[a-z]+\.[a-z]+$',
    # 匹配连续辅音字母超过7个的情况
    r'.*[bcdfghjklmnpqrstvwxyz]{7,}.*',
    # 长数字段域名
    r'\.\d{4,}\.(com|net|cn|org|info|biz|cc|tv)$',  
    # 随机字符串组合
    r'^[a-z0-9]{8,}\.[a-z0-9]{4,}\.\d+\.',  
    # 过度嵌套
    r'^([a-z0-9]+\.){5,}',  
    # 异常数字前缀
    r'\.\dwww\.',
    r'\.\d+www\.',  
    # 连续长数字
    r'\.\d{6,}', 
    # 包含多个连续数字的随机字符串
    r'[a-z]+\d{3,}[a-z]+',
    # 排除长度异常的子域名部分（超过20个字符）
    r'^[a-z0-9]{20,}\.',
    # 恶意/垃圾模式
    r'^[a-f0-9]{32,}',  # 长MD5/HASH
    r'[a-z]{10,}\d{5,}[a-z]{5,}',  # 混合长随机
    r'([a-z])\1{4,}',  # 同一字符重复5次以上
]

# CDN检测规则
CDN_DOMAINS = {
    "akamai.net", "akamaiedge.net", "edgesuite.net", "edgekey.net",
    "cloudfront.net", "fastly.net", "cdn77.org", "cloudflare.net",
    "alicdn.com", "aliyuncs.com", "alikunlun.com", "alikunlun.net",
    "tbcache.com", "cdngslb.com", "kunlun.com", "kunluncan.com",
    "azureedge.net", "msecnd.net", "mschcdn.com", "v0cdn.net",
    "wswebcdn.com", "lxdns.com", "wswebpic.com", "chinanetcenter.com",
    "customcdn.cn", "customcdn.com.cn", "51cdn.com", "wscdns.com",
    "cdn20.com", "wsdvs.com", "wsglb0.com", "cdn77.net", "incapdns.net",
    "kxcdn.com", "keycdn.com", "hwcdn.net", "stackpathdns.com",
    "stackpathcdn.com", "netdna-cdn.com", "netdna-ssl.com",
    "belugacdn.com", "cachefly.net", "footprint.net", "llnwd.net",
    "lldns.net", "simplecdn.net", "swiftserve.com", "bitgravity.com",
    "cdnetworks.net", "txcdn.cn", "cdnunion.net", "mygslb.com",
    "speedcdns.com", "mwcloudcdn.com", "mwcname.com", "fwdns.net",
    "att-dsa.net", "azioncdn.net", "inscname.net", "internapcdn.net",
    "unud.net", "mncdn.com", "rncdn1.com", "zenedge.net",
    "cdnhwc1.com", "cdnhwc2.com", "cdnhwc3.com", "cdnhwc4.com",
    "cdnhwc5.com", "cdnhwc6.com", "cdnhwc7.com", "cdnhwc8.com",
    "cdnhwc9.com", "cdnhwc10.com", "cdnhwc11.com", "cdnhwc12.com",
    "cdnhwc13.com", "cdnhwc14.com", "cdnhwc15.com", "cdnhwc16.com",
    "cdnhwc17.com", "cdnhwc18.com", "cdnhwc19.com", "cdnhwc20.com",
    "bdydns.com", "yunjiasu-cdn.net", "ccgslb.com", "ccgslb.net",
    "ccgslb.com.cn", "c3cache.net", "c3dns.net", "chinacache.net",
    "cdnudns.com", "sprycdn.com", "chuangcdn.com", "ctxcdn.cn",
    "yfcdn.net", "mmycdn.cn", "cnispgroup.com", "chinamaincloud.com",
    "cdnle.com", "gosuncdn.com", "mmtrixopt.com", "cloudfence.cn",
    "ngaagslb.cn", "p2cdn.com", "00cdn.com", "lccdn.org",
    "nscloudwaf.com", "2cname.com", "ucloudgda.com", "ncname.com",
    "alipaydns.com", "wscloudcdn.com", "saaswaf.com", "dbappwaf.cn",
    "glvs.com", "v6lvs.com", "haotaomi.com", "cloudcdns.com",
    "yundundns.com", "yundunwaf2.com", "qiniudns.com", "qbox.me",
    "aicdn.com", "momentcdn.com", "cdntip.com", "dnsv1.com",
    "tencdns.net", "dayugslb.com", "tcdnvod.com", "tdnsv5.com",
    "ksyuncdn.com", "ks-cdn.com", "ksyuncdn-k1.com", "verycdn.net",
    "verygslb.com", "xundayun.com", "xundayun.cn", "speedycloud.cc",
    "cdnify.io", "cdnsun.net", "jcloudcs.com", "jdcdn.com",
    "qianxun.com", "jcloudlb.com", "jcloud-cdn.com", "maoyun.tv",
    "maoyundns.com", "xgslb.net", "ucloud.cn", "ucloud.com.cn",
    "cdndo.com", "zenlogic.net", "ogslb.com", "uxengine.net",
    "tan14.net", "verycloud.cn", "mucdn.net", "nucdn.net",
    "alphacdn.net", "systemcdn.net", "edgecastcdn.net", "zetacdn.net",
    "coding.io", "coding.me", "gitlab.io", "github.io",
    "herokuapp.com", "googleapis.com", "netdna.com", "quic.cloud",
    "flexbalancer.net", "gcdn.co", "sangfordns.com", "stspg-customer.com",
    "turbobytes.net", "turbobytes-cdn.com", "1e100.net", "hdslb.net",
    "hdslb.com", "xwaf.cn", "shifen.com", "sinajs.cn", "tencent-cloud.net",
    "elemecdn.com", "sinaedge.com", "sina.com.cn", "sinacdn.com",
    "sinasws.com", "saebbs.com", "websitecname.cn", "cdncenter.cn",
    "vhostgo.com", "jsd.cc", "powercdn.cn", "21vokglb.cn", "21vianet.com.cn",
    "21okglb.cn", "21speedcdn.com", "21cvcdn.com", "okcdn.com", "okglb.com",
    "cdnnetworks.com", "cdnunion.com", "sprycdn.com", "chuangcdn.com",
    "aocde.com", "ctxcdn.cn", "yfcdn.net", "mmycdn.cn", "chinamaincloud.com",
    "cnispgroup.com", "cdnle.com", "gosuncdn.com", "mmtrixopt.com",
    "cloudfence.cn", "ngaagslb.cn", "p2cdn.com", "00cdn.com", "sankuai.com",
    "lccdn.org", "nscloudwaf.com", "2cname.com", "ucloudgda.com", "1e100.net",
    "alipaydns.com", "wscloudcdn.com", "saaswaf.com", "dbappwaf.cn",
    "glvs.com", "v6lvs.com", "haotaomi.com", "cloudcdns.com", "yundundns.com",
    "yundunwaf2.com"
}

# CDN IP段
CDN_IPS = [
    "223.4.77.85",  # ALLELINK
]

# DNS服务器列表
DNS_SERVERS = [
    "114.114.114.114",  # 114DNS
    "223.5.5.5",        # 阿里DNS
    "8.8.8.8",          # Google DNS
    "1.1.1.1",          # Cloudflare DNS
]

# 全局变量
ip_domain_map = {}  # IP到域名的映射
scan_summary = {    # 扫描汇总信息
    'targets': {},
    'ips_with_ports': {},
    'web_services': []
}

def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='端口安全扫描工具 - 真实IP查找、全端口扫描、服务识别')
    parser.add_argument('-f', '--target-file', default='targets.txt', 
                       help='目标文件，每行一个域名或IP')
    parser.add_argument('--real-ips-file', default='real_ips.txt',
                       help='真实IP地址输出文件')
    parser.add_argument('--web-urls-file', default='web_urls.txt',
                       help='Web地址输出文件')
    parser.add_argument('--domain-ip-file', default='domain_ip_map.txt',
                       help='域名与IP对应关系输出文件')
    parser.add_argument('--summary-file', default='scan_summary.txt',
                       help='扫描汇总报告输出文件')
    parser.add_argument('-t', '--threads', type=int, default=20,
                       help='线程数')
    parser.add_argument('--rate', type=int, default=2000,
                       help='masscan扫描速率')
    parser.add_argument('--port-batch-size', type=int, default=5000,
                       help='每批次扫描的端口数量，用于分块扫描 (默认: 5000)')
    parser.add_argument('--ip-batch-size', type=int, default=10,
                       help='每批次扫描的IP数量，用于分块扫描 (默认: 10)')
    parser.add_argument('--skip-masscan', action='store_true',
                       help='跳过端口扫描')
    parser.add_argument('--skip-nmap', action='store_true',
                       help='跳过服务识别')
    
    return parser.parse_args()

def check_tools():
    """检查所需工具是否存在"""
    tools = ['masscan']
    
    for tool in tools:
        if os.path.exists(f"./{tool}"):
            log_message("INFO", f"工具 {tool} 存在")
        else:
            log_message("WARNING", f"工具 {tool} 不存在于当前目录，请确保已放置")
            return False
    return True

def log_message(level, message):
    """日志记录"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_msg = f"[{timestamp}] [{level}] {message}"
    print(log_msg)

def is_valid_domain(domain):
    """检查域名是否有效，过滤掉明显无效的域名"""
    domain = domain.strip().lower()
    
    # 检查是否符合域名格式
    if not re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', domain):
        return False
    
    # 排除IP地址
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        return False
    
    # 应用过滤规则
    for pattern in DOMAIN_FILTER_PATTERNS:
        if re.search(pattern, domain):
            log_message("DEBUG", f"过滤域名: {domain} (匹配规则: {pattern})")
            return False
    
    # 检查域名层级（避免过多子域名）
    parts = domain.split('.')
    if len(parts) > 6:  # 限制域名层级
        log_message("DEBUG", f"过滤域名: {domain} (层级过多)")
        return False
    
    # 检查是否包含连续数字段
    for part in parts:
        if re.match(r'^\d{5,}$', part):  # 连续5位以上数字
            log_message("DEBUG", f"过滤域名: {domain} (包含长数字段)")
            return False
    
    # 检查子域名部分长度是否异常
    for part in parts[:-2]:  # 排除主域名和TLD
        if len(part) > 20:  # 子域名部分过长
            log_message("DEBUG", f"过滤域名: {domain} (子域名部分过长)")
            return False
    
    return True

def filter_domains(domains):
    """过滤域名列表，去除无效域名"""
    valid_domains = []
    invalid_count = 0
    
    for domain in domains:
        if is_valid_domain(domain):
            valid_domains.append(domain)
        else:
            invalid_count += 1
    
    log_message("INFO", f"域名过滤完成: 有效 {len(valid_domains)} 个，过滤 {invalid_count} 个")
    return valid_domains

def run_command(cmd, timeout=10):
    """执行命令并返回结果"""
    try:
        log_message("INFO", f"执行命令: {cmd}")
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=timeout
        )
        if result.returncode != 0:
            log_message("WARNING", f"命令执行失败: {result.stderr}")
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        log_message("ERROR", f"命令执行超时: {cmd}")
        return "", "Timeout", -1
    except Exception as e:
        log_message("ERROR", f"命令执行异常: {e}")
        return "", str(e), -1

def check_cdn_by_domain(domain):
    """检查域名是否属于CDN"""
    for cdn_domain in CDN_DOMAINS:
        if cdn_domain in domain:
            return True
    return False

def check_cdn_by_ip(ip):
    """检查IP是否属于CDN"""
    for cdn_ip in CDN_IPS:
        if ip == cdn_ip:
            return True
    return False

def get_cname(domain, dns_server="8.8.8.8"):
    """获取域名的CNAME记录"""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        resolver.timeout = 5
        resolver.lifetime = 5
        
        answers = resolver.resolve(domain, 'CNAME')
        cnames = [str(rdata.target).rstrip('.') for rdata in answers]
        return cnames
    except Exception as e:
        return []

def resolve_domain(domain):
    """解析域名获取IP，尝试绕过CDN"""
    log_message("INFO", f"解析域名: {domain}")
    
    # 检查域名是否直接匹配CDN
    if check_cdn_by_domain(domain):
        log_message("WARNING", f"域名 {domain} 匹配CDN模式，跳过")
        return []
    
    # 获取CNAME记录
    all_cnames = []
    for dns_server in DNS_SERVERS:
        try:
            cnames = get_cname(domain, dns_server)
            all_cnames.extend(cnames)
            
            # 检查CNAME是否包含CDN特征
            for cname in cnames:
                if check_cdn_by_domain(cname):
                    log_message("WARNING", f"CNAME {cname} 匹配CDN，跳过域名 {domain}")
                    return []
        except:
            continue
    
    # 尝试通过多个DNS服务器解析A记录
    ip_set = set()
    for dns_server in DNS_SERVERS:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server]
            resolver.timeout = 5
            resolver.lifetime = 5
            
            answers = resolver.resolve(domain, 'A')
            for rdata in answers:
                ip = str(rdata)
                # 检查IP是否属于CDN
                if not check_cdn_by_ip(ip):
                    ip_set.add(ip)
                    
                    # 更新IP到域名的映射
                    if ip not in ip_domain_map:
                        ip_domain_map[ip] = set()
                    ip_domain_map[ip].add(domain)
                    
                    log_message("INFO", f"从 {dns_server} 解析到IP: {ip}")
        except Exception as e:
            continue
    
    return list(ip_set)

def read_targets(target_file):
    """读取目标文件，自动区分域名和IP，并过滤无效域名"""
    if not os.path.exists(target_file):
        log_message("ERROR", f"目标文件 {target_file} 不存在")
        return [], []
    
    domains = []
    ips = []
    
    with open(target_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            # 判断是IP还是域名
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', line):
                ips.append(line)
            else:
                domains.append(line)
    
    # 过滤域名
    filtered_domains = filter_domains(domains)
    
    log_message("INFO", f"读取目标: 原始域名 {len(domains)} 个，过滤后 {len(filtered_domains)} 个，IP {len(ips)} 个")
    
    # 保存到汇总信息
    scan_summary['targets'] = {
        'original_domains': len(domains),
        'filtered_domains': len(filtered_domains),
        'ips': len(ips),
        'domains_list': filtered_domains,
        'ips_list': ips
    }
    
    return filtered_domains, ips

def bypass_cdn_and_get_ips(domains):
    """绕过CDN获取真实IP"""
    if not domains:
        log_message("WARNING", "没有域名需要解析")
        return []
    
    log_message("INFO", "开始CDN绕过和IP获取...")
    
    real_ips = set()
    real_domains = []
    
    with ThreadPoolExecutor(max_workers=CONFIG['threads']) as executor:
        futures = {executor.submit(resolve_domain, domain): domain for domain in domains}
        
        for future in as_completed(futures):
            domain = futures[future]
            try:
                ips = future.result(timeout=5)
                if ips:
                    for ip in ips:
                        real_ips.add(ip)
                    real_domains.append(domain)
                    log_message("SUCCESS", f"域名 {domain} -> IP: {', '.join(ips)}")
                else:
                    log_message("WARNING", f"域名 {domain} 无法获取真实IP")
            except Exception as e:
                log_message("ERROR", f"处理域名 {domain} 时出错: {e}")
    
    # 保存域名与IP的对应关系
    save_domain_ip_map()
    
    log_message("INFO", f"获取到 {len(real_ips)} 个真实IP")
    
    # 保存到汇总信息
    scan_summary['cdn_bypass'] = {
        'resolved_domains': len(real_domains),
        'real_ips': len(real_ips),
        'domain_ip_map': ip_domain_map.copy()
    }
    
    return list(real_ips)

def save_domain_ip_map():
    """保存域名与IP的对应关系"""
    with open(CONFIG['domain_ip_file'], 'w') as f:
        f.write("# 域名与真实IP对应关系\n")
        f.write("# 生成时间: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
        f.write("# 格式: 域名 -> IP1, IP2, ...\n\n")
        
        for ip, domains in ip_domain_map.items():
            domain_list = ', '.join(domains)
            f.write(f"{domain_list} -> {ip}\n")
    
    log_message("INFO", f"域名与IP对应关系已保存到: {CONFIG['domain_ip_file']}")

def save_real_ips(real_ips):
    """保存真实IP地址"""
    with open(CONFIG['real_ips_file'], 'w') as f:
        f.write("# 真实IP地址列表\n")
        f.write("# 生成时间: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
        f.write("# 总数: " + str(len(real_ips)) + "\n\n")
        
        for ip in real_ips:
            f.write(ip + "\n")
    
    log_message("INFO", f"真实IP地址已保存到: {CONFIG['real_ips_file']}")
    
    # 保存到汇总信息
    scan_summary['real_ips'] = real_ips

def run_command_with_realtime_output(cmd, timeout=30000):
    """执行命令并实时输出结果"""
    log_message("INFO", f"开始执行命令: {cmd}")
    
    try:
        process = subprocess.Popen(
            cmd, 
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        start_time = time.time()
        last_output_time = time.time()
        output_lines = 0
        
        # 实时读取输出
        while True:
            # 检查超时
            if timeout and time.time() - start_time > timeout:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except:
                    process.kill()
                log_message("ERROR", f"命令执行超时: {cmd}")
                return "", "Timeout", -1
            
            # 读取标准输出
            try:
                output = process.stdout.readline()
                if output:
                    output_lines += 1
                    last_output_time = time.time()
                    output = output.strip()
                    if output:
                        print(f"[MASS] {output}")
            except Exception as e:
                # 非阻塞读取可能抛出异常，继续执行
                pass
            
            # 读取错误输出
            try:
                err_output = process.stderr.readline()
                if err_output:
                    err_output = err_output.strip()
                    if err_output:
                        print(f"[MASS-ERR] {err_output}")
            except:
                pass
            
            # 检查进程是否结束
            returncode = process.poll()
            if returncode is not None:
                # 读取剩余输出
                remaining_output = process.stdout.read()
                if remaining_output:
                    for line in remaining_output.strip().split('\n'):
                        if line.strip():
                            print(f"[MASS] {line.strip()}")
                
                # 读取剩余错误输出
                stderr_output = process.stderr.read()
                
                return "", stderr_output, returncode
            
            time.sleep(0.01)  # 稍微降低CPU占用
            
    except Exception as e:
        log_message("ERROR", f"命令执行异常: {e}")
        import traceback
        traceback.print_exc()
        return "", str(e), -1

def batch_masscan_scan(ips, rate, batch_size=5000, ip_batch_size=10):
    """分批扫描全端口（1-65535），每批5000个端口，同时按10个IP一批进行IP分批"""
    open_ports_by_ip = {}
    
    # 第一步：将IP分批
    ip_batches = []
    for i in range(0, len(ips), ip_batch_size):
        ip_batch = ips[i:i+ip_batch_size]
        ip_batches.append(ip_batch)
    
    log_message("INFO", f"IP分批完成: {len(ips)} 个IP分成 {len(ip_batches)} 批，每批最多 {ip_batch_size} 个IP")
    
    # 计算总端口数和端口批次
    all_ports = list(range(1, 65536))
    total_ports = len(all_ports)
    port_batches = (total_ports + batch_size - 1) // batch_size
    
    log_message("INFO", f"全端口扫描策略: {port_batches} 个端口批次，每批 {batch_size} 个端口")
    log_message("INFO", f"总扫描单元数: {len(ip_batches)} IP批次 × {port_batches} 端口批次 = {len(ip_batches)*port_batches} 个扫描单元")
    
    start_time = time.time()
    total_scan_units = len(ip_batches) * port_batches
    completed_scan_units = 0
    
    # 第二步：按IP批次和端口批次进行双重循环扫描
    for ip_batch_idx, ip_batch in enumerate(ip_batches):
        log_message("INFO", f"开始扫描第 {ip_batch_idx+1}/{len(ip_batches)} IP批次，包含 {len(ip_batch)} 个IP")
        
        # 为当前IP批次创建IP文件
        ip_batch_file = f'masscan_targets_ipbatch_{ip_batch_idx}.txt'
        with open(ip_batch_file, 'w') as f:
            for ip in ip_batch:
                f.write(ip + '\n')
        
        # 动态维护当前IP批次的活跃IP
        active_ips = list(ip_batch)  # 复制一份
        skipped_ips_in_batch = set()  # 记录当前批次跳过的IP
        
        # 第三步：对当前IP批次进行端口分批扫描
        for port_batch_idx in range(port_batches):
            start_port = port_batch_idx * batch_size + 1
            end_port = min((port_batch_idx + 1) * batch_size, total_ports)
            
            # 检查当前IP批次是否还有活跃IP
            if not active_ips:
                log_message("INFO", f"IP批次 {ip_batch_idx+1} 的所有IP都已跳过，跳过剩余的端口批次")
                completed_scan_units += (port_batches - port_batch_idx)
                break
            
            # 计算当前扫描单元进度
            completed_scan_units += 1
            overall_progress = (completed_scan_units / total_scan_units) * 100
            
            # 每10个扫描单元或每30秒输出一次进度
            current_time = time.time()
            if (completed_scan_units % 10 == 0 or 
                (current_time - start_time) > 30 or 
                completed_scan_units == total_scan_units):
                
                elapsed = current_time - start_time
                eta = (elapsed / completed_scan_units) * (total_scan_units - completed_scan_units) if completed_scan_units > 0 else 0
                
                log_message("INFO", 
                          f"总体进度: {completed_scan_units}/{total_scan_units} ({overall_progress:.1f}%)，"
                          f"IP批次: {ip_batch_idx+1}/{len(ip_batches)}，"
                          f"端口批次: {port_batch_idx+1}/{port_batches}，"
                          f"已运行: {elapsed/60:.1f}分钟，"
                          f"预计剩余: {eta/60:.1f}分钟")
            
            # 为当前IP批次和端口批次创建IP文件（只包含活跃IP）
            current_ip_file = f'masscan_targets_ip{ip_batch_idx}_port{port_batch_idx}.txt'
            with open(current_ip_file, 'w') as f:
                for ip in active_ips:
                    f.write(ip + '\n')
            
            # 构建命令
            cmd = (f"./masscan -iL {current_ip_file} -p{start_port}-{end_port} "
                   f"--rate={rate} "
                   f"--max-retries 1 "
                   f"-oJ masscan_ip{ip_batch_idx}_port{port_batch_idx}.json")
            
            # 计算超时时间
            estimated_targets = (end_port - start_port + 1) * len(active_ips)
            timeout = max(50, estimated_targets / rate * 2)  # 最少50秒
            
            log_message("DEBUG", 
                       f"扫描单元 {completed_scan_units}/{total_scan_units}: "
                       f"IP批次{ip_batch_idx+1}端口{start_port}-{end_port}，"
                       f"活跃IP: {len(active_ips)}，超时: {timeout:.0f}秒")
            
            # 执行扫描
            stdout, stderr, returncode = run_command_with_realtime_output(cmd, timeout=timeout)
            
            # 检查命令执行状态
            if returncode != 0:
                log_message("WARNING", 
                           f"扫描单元 {completed_scan_units} 失败，返回码: {returncode}")
                if stderr:
                    log_message("WARNING", f"错误信息: {stderr[:200]}")
            
            # 解析当前批次结果
            batch_file = f'masscan_ip{ip_batch_idx}_port{port_batch_idx}.json'
            batch_results = parse_masscan_results(batch_file)
            
            # 合并结果
            for ip, ports in batch_results.items():
                if ip not in open_ports_by_ip:
                    open_ports_by_ip[ip] = []
                open_ports_by_ip[ip].extend(ports)
            
            # 清理当前扫描单元的临时文件
            if os.path.exists(current_ip_file):
                os.remove(current_ip_file)
            if os.path.exists(batch_file):
                os.remove(batch_file)
            
            # 每个扫描单元之间休息0.1秒，避免过度占用资源
            if completed_scan_units < total_scan_units:
                time.sleep(0.1)
        
        # 清理当前IP批次的临时文件
        if os.path.exists(ip_batch_file):
            os.remove(ip_batch_file)
        
        # 输出当前IP批次的统计
        total_ports_in_batch = sum(len(open_ports_by_ip.get(ip, [])) for ip in ip_batch)
        log_message("INFO", 
                   f"IP批次 {ip_batch_idx+1} 完成: "
                   f"{len(ip_batch)} 个IP，"
                   f"{total_ports_in_batch} 个开放端口")
        
        # 每完成一个IP批次，休息1秒
        if ip_batch_idx < len(ip_batches) - 1:
            time.sleep(1)
    
    # 扫描完成统计
    elapsed_time = time.time() - start_time
    total_ports_found = sum(len(ports) for ports in open_ports_by_ip.values())
    total_ips_with_ports = len([ip for ip, ports in open_ports_by_ip.items() if ports])
    
    log_message("INFO", f"全端口扫描完成，实际耗时: {elapsed_time/60:.1f}分钟")
    log_message("INFO", f"初始IP数量: {len(ips)}")
    log_message("INFO", f"发现开放端口的IP数量: {total_ips_with_ports}")
    log_message("INFO", f"发现的开放端口总数: {total_ports_found}")
    
    return open_ports_by_ip

def parse_masscan_results(filename):
    """解析Masscan JSON结果文件"""
    open_ports_by_ip = {}
    
    if not os.path.exists(filename):
        return open_ports_by_ip
    
    try:
        with open(filename, 'r') as f:
            content = f.read().strip()
            
            if not content:
                return open_ports_by_ip
            
            # 处理Masscan JSON格式
            if not content.startswith('['):
                lines = content.strip().split('\n')
                json_lines = []
                for line in lines:
                    if line.strip():
                        json_lines.append(line.strip())
                if json_lines:
                    formatted_content = '[' + ','.join(json_lines) + ']'
                else:
                    return open_ports_by_ip
            else:
                formatted_content = content
            
            data = json.loads(formatted_content)
            
            for item in data:
                if 'ip' in item and 'ports' in item and item['ports']:
                    ip = item['ip']
                    port = item['ports'][0]['port']
                    
                    if ip not in open_ports_by_ip:
                        open_ports_by_ip[ip] = []
                    
                    open_ports_by_ip[ip].append(port)
                    
    except Exception as e:
        log_message("WARNING", f"解析文件 {filename} 失败: {e}")
    
    return open_ports_by_ip

def masscan_scan(ips, skip=False, rate=2000, port_batch_size=5000, ip_batch_size=10):
    """使用masscan进行全端口扫描"""
    if skip:
        log_message("INFO", f"跳过端口扫描")
        return [], {}
    
    log_message("INFO", f"开始Masscan全端口扫描 (1-65535)...")
    
    if not ips:
        log_message("WARNING", "没有IP可扫描")
        return [], {}
    
    # 使用分批扫描全端口
    open_ports_by_ip = batch_masscan_scan(ips, rate, port_batch_size, ip_batch_size)
    
    # 去重并排序端口
    for ip in open_ports_by_ip:
        open_ports_by_ip[ip] = sorted(set(open_ports_by_ip[ip]))
    
    # 检查端口数量阈值并过滤
    filtered_ips = []
    for ip, ports in open_ports_by_ip.items():
        if len(ports) <= CONFIG['skip_port_threshold']:
            filtered_ips.append(ip)
            if len(ports) > 0:
                log_message("INFO", f"IP {ip} 开放 {len(ports)} 个端口")
                # 如果端口数量少于10则在打印日志中完全显示，否则只显示前10个端口
                if len(ports) <= 10:
                    log_message("INFO", f"  端口列表: {ports}")
                else:
                    log_message("INFO", f"  端口列表: {ports[:10]}... 等 {len(ports)} 个端口")
        else:
            log_message("WARNING", f"IP {ip} 开放端口数 {len(ports)} > {CONFIG['skip_port_threshold']}，跳过")
    
    total_ports_found = sum(len(ports) for ports in open_ports_by_ip.values())
    total_ips_with_ports = len([ip for ip, ports in open_ports_by_ip.items() if ports])
    
    log_message("INFO", 
               f"Masscan扫描完成: {total_ips_with_ports}个IP有开放端口，"
               f"共发现 {total_ports_found} 个开放端口，{len(filtered_ips)} 个有效IP")
    
    # 保存到汇总信息
    scan_summary['masscan_results'] = {
        'total_ips': len(ips),
        'ips_with_open_ports': total_ips_with_ports,
        'total_ports_found': total_ports_found,
        'filtered_ips': filtered_ips,
        'open_ports_by_ip': open_ports_by_ip.copy()
    }
    
    return filtered_ips, open_ports_by_ip

def get_http_info(url, timeout=5):
    """获取HTTP状态码和页面标题"""
    try:
        response = requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        )
        
        status_code = response.status_code
        title = "N/A"
        
        # 尝试提取标题
        if 'text/html' in response.headers.get('Content-Type', '').lower():
            soup = BeautifulSoup(response.content, 'html.parser')
            if soup.title and soup.title.string:
                title = soup.title.string.strip()[:100]  # 限制标题长度
        
        return {
            'url': url,
            'status_code': status_code,
            'title': title,
            'headers': dict(response.headers)
        }
    except requests.exceptions.Timeout:
        return {'url': url, 'status_code': 'Timeout', 'title': 'N/A'}
    except requests.exceptions.SSLError:
        # 尝试使用http
        if url.startswith('https://'):
            http_url = url.replace('https://', 'http://', 1)
            return get_http_info(http_url, timeout)
        return {'url': url, 'status_code': 'SSL Error', 'title': 'N/A'}
    except Exception as e:
        return {'url': url, 'status_code': f'Error: {str(e)[:50]}', 'title': 'N/A'}

def nmap_service_scan(ips_with_ports, skip=False):
    """使用nmap进行服务识别，并获取HTTP信息"""
    if skip:
        log_message("INFO", "跳过服务识别")
        return []
    
    log_message("INFO", "开始Nmap服务识别...")
    
    web_urls = []  # 存储URL列表
    web_services = []  # 存储Web服务详细信息
    ip_services = {}  # 存储IP的端口服务信息
    
    for ip, ports in ips_with_ports.items():
        if not ports:
            continue
        
        # 将端口列表转换为逗号分隔的字符串
        ports_str = ','.join(map(str, ports))
        
        log_message("INFO", f"扫描 {ip} 的端口: {ports_str}")
        
        # 执行nmap扫描
        cmd = f"nmap -sV -p {ports_str} {ip} -oX {CONFIG['nmap_output']}.{ip.replace('.', '_')}"
        stdout, stderr, returncode = run_command(cmd, timeout=600)
        
        # 解析nmap XML输出
        xml_file = f"{CONFIG['nmap_output']}.{ip.replace('.', '_')}"
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            ip_services[ip] = []
            
            for host in root.findall('host'):
                for ports_elem in host.findall('ports'):
                    for port_elem in ports_elem.findall('port'):
                        portid = port_elem.get('portid')
                        protocol = port_elem.get('protocol')
                        state_elem = port_elem.find('state')
                        
                        if state_elem is not None and state_elem.get('state') == 'open':
                            service_elem = port_elem.find('service')
                            service_name = "unknown"
                            product = "unknown"
                            version = "unknown"
                            
                            if service_elem is not None:
                                service_name = service_elem.get('name', 'unknown')
                                product = service_elem.get('product', 'unknown')
                                version = service_elem.get('version', 'unknown')
                            
                            # 记录端口服务信息
                            service_info = {
                                'port': portid,
                                'protocol': protocol,
                                'service': service_name,
                                'product': product,
                                'version': version
                            }
                            ip_services[ip].append(service_info)
                            
                            # 检查是否是web服务
                            if 'http' in service_name or 'https' in service_name or 'http' in product.lower():
                                protocol = 'https' if service_name == 'https' or '443' in portid else 'http'
                                
                                # 添加IP URL
                                ip_url = f"{protocol}://{ip}:{portid}"
                                web_urls.append(ip_url)
                                
                                # 获取HTTP信息
                                http_info = get_http_info(ip_url)
                                
                                # 记录Web服务详细信息
                                web_service = {
                                    'url': ip_url,
                                    'type': 'ip',
                                    'ip': ip,
                                    'port': portid,
                                    'service': service_name,
                                    'product': product,
                                    'version': version,
                                    'status_code': http_info['status_code'],
                                    'title': http_info['title']
                                }
                                web_services.append(web_service)
                                
                                # 检查是否有域名绑定到这个IP
                                if ip in ip_domain_map and ip_domain_map[ip]:
                                    for domain in ip_domain_map[ip]:
                                        if portid in ['80', '443']:
                                            domain_url = f"{protocol}://{domain}"
                                        else:
                                            domain_url = f"{protocol}://{domain}:{portid}"
                                        
                                        web_urls.append(domain_url)
                                        
                                        # 获取HTTP信息
                                        domain_http_info = get_http_info(domain_url)
                                        
                                        # 记录域名Web服务详细信息
                                        domain_web_service = {
                                            'url': domain_url,
                                            'type': 'domain',
                                            'ip': ip,
                                            'domain': domain,
                                            'port': portid,
                                            'service': service_name,
                                            'product': product,
                                            'version': version,
                                            'status_code': domain_http_info['status_code'],
                                            'title': domain_http_info['title']
                                        }
                                        web_services.append(domain_web_service)
                                        
                                        log_message("INFO", f"域名绑定: {domain_url} - 状态码: {domain_http_info['status_code']}, 标题: {domain_http_info['title']}")
            
            # 删除临时文件
            if os.path.exists(xml_file):
                os.remove(xml_file)
            
        except Exception as e:
            log_message("ERROR", f"解析nmap XML失败: {e}")
            if os.path.exists(xml_file):
                os.remove(xml_file)
    
    # 去重URL
    web_urls = list(set(web_urls))
    
    # 保存web服务URL
    save_web_urls(web_urls)
    
    # 保存到汇总信息
    scan_summary['nmap_results'] = {
        'ip_services': ip_services,
        'web_services': web_services
    }
    
    log_message("INFO", f"Nmap扫描完成，发现 {len(web_services)} 个Web服务")
    return web_urls

def save_web_urls(web_urls):
    """保存Web地址"""
    with open(CONFIG['web_urls_file'], 'w') as f:
        f.write("# Web服务地址列表\n")
        f.write("# 生成时间: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
        f.write("# 总数: " + str(len(web_urls)) + "\n\n")
        
        for url in sorted(web_urls):
            f.write(url + "\n")
    
    log_message("INFO", f"Web地址已保存到: {CONFIG['web_urls_file']}")

def generate_summary_report():
    """生成扫描汇总报告"""
    log_message("INFO", "生成扫描汇总报告...")
    
    with open(CONFIG['summary_file'], 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("                    安全扫描汇总报告\n")
        f.write("=" * 80 + "\n\n")
        
        f.write(f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"目标文件: {CONFIG['target_file']}\n\n")
        
        # 1. 目标统计
        f.write("一、目标统计\n")
        f.write("-" * 40 + "\n")
        if 'targets' in scan_summary:
            targets = scan_summary['targets']
            f.write(f"原始域名数量: {targets['original_domains']}\n")
            f.write(f"过滤后域名数量: {targets['filtered_domains']}\n")
            f.write(f"直接IP数量: {targets['ips']}\n")
            f.write(f"总目标数: {targets['filtered_domains'] + targets['ips']}\n\n")
        
        # 2. CDN绕过结果
        f.write("二、CDN绕过结果\n")
        f.write("-" * 40 + "\n")
        if 'cdn_bypass' in scan_summary:
            cdn = scan_summary['cdn_bypass']
            f.write(f"成功解析的域名: {cdn['resolved_domains']}\n")
            f.write(f"获取到的真实IP: {cdn['real_ips']}\n\n")
        
        # 3. 真实IP列表
        f.write("三、真实IP地址列表\n")
        f.write("-" * 40 + "\n")
        if 'real_ips' in scan_summary:
            for ip in scan_summary['real_ips']:
                f.write(f"{ip}\n")
            f.write(f"\n总计: {len(scan_summary['real_ips'])} 个IP\n\n")
        
        # 4. 端口扫描结果
        f.write("四、端口扫描结果\n")
        f.write("-" * 40 + "\n")
        if 'masscan_results' in scan_summary:
            masscan = scan_summary['masscan_results']
            f.write(f"扫描IP总数: {masscan['total_ips']}\n")
            f.write(f"有开放端口的IP: {masscan['ips_with_open_ports']}\n")
            f.write(f"发现的开放端口总数: {masscan['total_ports_found']}\n")
            f.write(f"有效IP（端口数<={CONFIG['skip_port_threshold']}）: {len(masscan['filtered_ips'])}\n\n")
            
            # 每个IP的端口详情
            f.write("IP地址及开放端口详情:\n")
            for ip, ports in masscan['open_ports_by_ip'].items():
                if len(ports) <= CONFIG['skip_port_threshold']:
                    f.write(f"\n{ip}:\n")
                    f.write(f"  开放端口数: {len(ports)}\n")
                    f.write(f"  端口列表: {ports}\n")
        
        # 5. 服务识别结果
        f.write("\n五、服务识别结果\n")
        f.write("-" * 40 + "\n")
        if 'nmap_results' in scan_summary:
            nmap = scan_summary['nmap_results']
            
            # IP端口服务详情
            f.write("IP端口服务详情:\n")
            for ip, services in nmap['ip_services'].items():
                f.write(f"\n{ip}:\n")
                for service in services:
                    f.write(f"  端口: {service['port']}/{service['protocol']}\n")
                    f.write(f"    服务: {service['service']}\n")
                    f.write(f"    产品: {service['product']}\n")
                    f.write(f"    版本: {service['version']}\n")
            
            # Web服务详情
            f.write("\n六、Web服务详情\n")
            f.write("-" * 40 + "\n")
            f.write(f"发现Web服务总数: {len(nmap['web_services'])}\n\n")
            
            for i, web in enumerate(nmap['web_services'], 1):
                f.write(f"{i}. {web['url']}\n")
                f.write(f"   类型: {web['type']}\n")
                if web['type'] == 'domain':
                    f.write(f"   绑定IP: {web['ip']}\n")
                    f.write(f"   域名: {web['domain']}\n")
                f.write(f"   端口: {web['port']}\n")
                f.write(f"   服务: {web['service']}\n")
                f.write(f"   状态码: {web['status_code']}\n")
                f.write(f"   标题: {web['title']}\n")
                f.write(f"   产品: {web['product']}\n")
                if web['version'] != 'unknown':
                    f.write(f"   版本: {web['version']}\n")
                f.write("\n")
        
        # 6. 域名与IP对应关系
        f.write("\n七、域名与IP对应关系\n")
        f.write("-" * 40 + "\n")
        for ip, domains in ip_domain_map.items():
            domain_list = ', '.join(domains)
            f.write(f"{domain_list} -> {ip}\n")
        
        f.write("\n" + "=" * 80 + "\n")
        f.write("                    报告结束\n")
        f.write("=" * 80 + "\n")
    
    log_message("INFO", f"扫描汇总报告已保存到: {CONFIG['summary_file']}")

def cleanup_temp_files():
    """清理临时文件"""
    temp_files = [
        CONFIG['masscan_output'],
        'masscan_targets.txt',
    ]
    
    # 添加masscan临时文件
    for file in os.listdir('.'):
        if file.startswith('masscan_targets_ip') and file.endswith('.txt'):
            temp_files.append(file)
        if file.startswith('masscan_ip') and file.endswith('.json'):
            temp_files.append(file)
    
    # 添加nmap临时文件
    for file in os.listdir('.'):
        if file.startswith('nmap.xml.') and not file.endswith('.bak'):
            temp_files.append(file)
    
    for file in temp_files:
        if os.path.exists(file):
            try:
                os.remove(file)
                log_message("INFO", f"已清理临时文件: {file}")
            except:
                pass

def main():
    """主函数"""
    args = parse_arguments()
    
    # 更新配置
    CONFIG['target_file'] = args.target_file
    CONFIG['real_ips_file'] = args.real_ips_file
    CONFIG['web_urls_file'] = args.web_urls_file
    CONFIG['domain_ip_file'] = args.domain_ip_file
    CONFIG['summary_file'] = args.summary_file
    CONFIG['threads'] = args.threads
    
    log_message("INFO", "开始安全扫描")
    log_message("INFO", f"目标文件: {args.target_file}")
    log_message("INFO", f"输出文件: ")
    log_message("INFO", f"  1. 真实IP地址文件: {args.real_ips_file}")
    log_message("INFO", f"  2. Web地址文件: {args.web_urls_file}")
    log_message("INFO", f"  3. 域名与IP对应关系文件: {args.domain_ip_file}")
    log_message("INFO", f"  4. 扫描汇总报告文件: {args.summary_file}")
    log_message("INFO", f"扫描策略: 全端口扫描 (1-65535)，端口批次大小: {args.port_batch_size}，IP批次大小: {args.ip_batch_size}")
    
    # 检查工具
    if not check_tools():
        log_message("ERROR", "必需工具不存在，请将masscan放置在当前目录")
        return
    
    # 检查目标文件
    if not os.path.exists(CONFIG['target_file']):
        log_message("ERROR", f"目标文件 {CONFIG['target_file']} 不存在")
        return
    
    try:
        # 步骤1: 读取目标，区分域名和IP，并过滤无效域名
        domains, direct_ips = read_targets(CONFIG['target_file'])
        
        if not domains and not direct_ips:
            log_message("ERROR", "未发现可扫描的目标（无域名且无IP），退出扫描")
            return
        
        # 步骤2: 绕过CDN获取真实IP（仅对域名）
        real_ips_from_domains = []
        if domains:
            real_ips_from_domains = bypass_cdn_and_get_ips(domains)
        
        # 合并所有IP（域名解析出的IP + 直接提供的IP）
        all_ips = list(set(real_ips_from_domains + direct_ips))
        
        if not all_ips:
            log_message("ERROR", "未获取到可扫描的IP，退出扫描")
            return
        
        # 保存真实IP地址
        save_real_ips(all_ips)
        
        # 步骤3: Masscan全端口扫描
        filtered_ips, ips_with_ports = masscan_scan(
            all_ips, 
            skip=args.skip_masscan,
            rate=args.rate,
            port_batch_size=args.port_batch_size,
            ip_batch_size=args.ip_batch_size
        )
        
        # 过滤只有有效端口的IP
        filtered_ips_with_ports = {}
        for ip in filtered_ips:
            if ip in ips_with_ports and ips_with_ports[ip]:
                filtered_ips_with_ports[ip] = ips_with_ports[ip]
        
        if not filtered_ips_with_ports:
            log_message("WARNING", "未发现有效开放端口，跳过服务识别")
        else:
            # 步骤4: Nmap服务识别（获取Web地址）
            web_urls = nmap_service_scan(filtered_ips_with_ports, skip=args.skip_nmap)
        
        # 步骤5: 生成扫描汇总报告
        generate_summary_report()
        
        log_message("SUCCESS", "扫描完成！")
        log_message("INFO", f"1. 真实IP地址文件: {CONFIG['real_ips_file']}")
        log_message("INFO", f"2. Web地址文件: {CONFIG['web_urls_file']}")
        log_message("INFO", f"3. 域名与IP对应关系文件: {CONFIG['domain_ip_file']}")
        log_message("INFO", f"4. 扫描汇总报告文件: {CONFIG['summary_file']}")
        
    except KeyboardInterrupt:
        log_message("WARNING", "扫描被用户中断")
    except Exception as e:
        log_message("ERROR", f"扫描过程中出现错误: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # 清理临时文件
        cleanup_temp_files()

if __name__ == "__main__":
    if sys.version_info < (3, 6):
        print("需要Python 3.6或更高版本")
        sys.exit(1)
    
    main()
