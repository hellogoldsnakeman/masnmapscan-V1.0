# masnmapscan-V1.0
程序整合了masscan和nmap两款扫描器，masscan扫描端口，nmap扫描端口对应服务，二者结合起来实现了又快又好地扫描。并且加入了针对目标资产有防火墙的应对措施

安装说明及运行流程：
1、首先pip install -r requirements.txt安装所需插件。如果要扫描子域名，就将子域名保存到subdomain.txt里，放在masnmap.py同目录下；如果已经有ip地址，就将ip地址保存在ip.txt里，放在masnmap.py同目录下。
2、程序运行后会自动解析这些子域名对应的ip，ip经过去重后保存在ip.txt文件中。然后扫描这些ip开放的端口及对应的服务，将其中web地址标记出来。对最终的扫描结果进行去重，最终扫描结果保存在final_result.txt文件中。
3、扫描结果会生成4个文件：domain-ip.txt、ip.txt、final_result.txt和url.txt。domain-ip.txt里面是子域名和ip的对应关系，ip.txt里面是去重后的ip地址，final_result.txt里面是去重后的端口服务扫描结果，url.txt里面是从final_result.txt里提取出来的web地址。

本程序仅供于学习交流，请使用者遵守《中华人民共和国网络安全法》，勿将此工具用于非授权的测试，程序开发者不负任何连带法律责任。

