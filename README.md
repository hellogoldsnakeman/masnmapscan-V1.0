# masnmapscan-V1.0
程序整合了masscan和nmap两款扫描器，masscan扫描端口，nmap扫描端口对应服务，二者结合起来实现了又快又好地扫描。  

### 20251126版主要更新了如下内容：  
1、使用python3编写  

2、增加了绕过CDN发现真实ip的功能

### 20230306版主要更新了如下内容：  
1、支持域名解析。将子域名解析为ip地址。  

2、优化服务识别。之前的版本会将一些web服务识别为其他服务，造成web地址的漏报。这一版对nmap扫描参数进行了调整，修复了这个问题。  

3、可以实时查看扫描结果。之前的版本将扫描过程临时保存在一个数组里，所以只有全部扫描完成后才能查看扫描结果，一旦扫描过程中断就前功尽弃了，这一版可以实时查看结果。  

4、优化扫描结果展示。对扫描结果展示进行了优化，说白了就是扫描结果比之前清晰好看了一些。  

5、修复了某些情况下中文显示乱码  

### 安装说明及运行流程：  
1、首先pip3 install -r requirements.txt安装所需插件。将masscan放在masnmapscan同目录下，如果要扫描子域名，就将子域名保存到txt文档里，放在masnmapscan.py同目录下；如果已经有ip地址，就将ip地址保存在ip.txt里，放在masnmapscan.py同目录下。  

2、程序运行后会自动解析这些子域名，并找到子域名对应的真实ip，ip经过去重后保存在real_ips.txt文件中。然后扫描这些ip开放的端口及对应的服务，将其中web地址标记出来。对最终的扫描结果进行去重，最终扫描结果保存在final_result.txt文件中。  

3、扫描结果会生成4个文件：domain_ip_mapping.txt、real_ips.txt、final_result.txt和url.txt。domain_ip_mapping.txt里面是子域名和ip的对应关系，real_ips.txt里面是去重后的ip地址，final_result.txt里面是去重后的端口服务扫描结果，url.txt里面是从final_result.txt里提取出来的web地址。  

### 应用场景
这款工具只是作为信息收集链中的一个环节，不求大而全，只求在其中某一个点能有所用处。比如先使用oneforall、subfinder等工具收集到子域名，然后用masnmapscan扫描子域名对应的ip和端口，生成后的web文档可以直接投喂给dirsearch、jsfinder、nuclei、xray等工具进行下一步扫描。可以起到一个承上启下的作用。

### 使用说明：  
python3 masnmapscan.py -h

单个域名: python3 masnmapscan.py -d example.com

批量域名: python3 masnmapscan.py -f domains.txt

直接扫描ip：python3 masnmapscan.py --skip-realip --ip-file ip.txt

### 代码没有延续以往的简单粗暴，任意所至，增加了部分杠这杠那的参数选项，不同于以往随心所欲，上来就干的风格，简约之下更显沉稳，不足之处请大家批评指正。  
### 本程序仅供于学习交流，请使用者遵守《中华人民共和国网络安全法》，勿将此工具用于非授权的测试。

