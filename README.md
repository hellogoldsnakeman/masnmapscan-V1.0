# masnmapscan-V1.0
程序整合了masscan和nmap两款扫描器，masscan扫描端口，nmap扫描端口对应服务，二者结合起来实现了又快又好地扫描。  
新版主要更新了如下内容：  
1、支持域名解析。将子域名解析为ip地址。  

2、优化服务识别。之前的版本会将一些web服务识别为其他服务，造成web地址的漏报。这一版对nmap扫描参数进行了调整，修复了这个问题。  

3、可以实时查看扫描结果。之前的版本将扫描过程临时保存在一个数组里，所以只有全部扫描完成后才能查看扫描结果，一旦扫描过程中断就前功尽弃了，这一版可以实时查看结果。  

4、优化扫描结果展示。对扫描结果展示进行了优化，说白了就是扫描结果比之前清晰好看了一些。  

5、修复了某些情况下中文显示乱码  

安装说明及运行流程：  
1、首先pip install -r requirements.txt安装所需插件。如果要扫描子域名，就将子域名保存到subdomain.txt里，放在masnmap.py同目录下；如果已经有ip地址，就将ip地址保存在ip.txt里，放在masnmap.py同目录下。  

2、程序运行后会自动解析这些子域名对应的ip，ip经过去重后保存在ip.txt文件中。然后扫描这些ip开放的端口及对应的服务，将其中web地址标记出来。对最终的扫描结果进行去重，最终扫描结果保存在final_result.txt文件中。  

3、扫描结果会生成4个文件：domain-ip.txt、ip.txt、final_result.txt和url.txt。domain-ip.txt里面是子域名和ip的对应关系，ip.txt里面是去重后的ip地址，final_result.txt里面是去重后的端口服务扫描结果，url.txt里面是从final_result.txt里提取出来的web地址。  


用python2开发的：  
Usage: python masnmapscan.py  

本程序仅供于学习交流，请使用者遵守《中华人民共和国网络安全法》，勿将此工具用于非授权的测试。

