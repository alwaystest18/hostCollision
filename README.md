# hostCollision

一款host碰撞工具



## 介绍

host碰撞可以帮助安全测试人员更好的发现隐藏资产，测试了搜到的host碰撞工具，发现最大的问题是误报比较多，因此动手写了这个工具，本程序最大的优点就是误报比较少（速率配置合理的情况下，否则网络抖动导致请求超时会出现漏报）。使用直接ip请求+不存在的host请求提取特征，内容较少通过状态码与页面长度判断，内容较多则通过页面相似度判断。



## 安装

```
git clone https://github.com/alwaystest18/hostCollision.git
cd hostCollision/
go install
go build hostCollision.go
```



## 使用

速度测试：家庭宽带环境，默认线程+限速，812个站点碰撞一个host耗时35s

参数说明

```
Usage of ./hostCollision:
  -df string   //待碰撞的域名列表文件，每行一个，格式为xxx.xxx.com
        domain file path
  -o string   //碰撞成功的保存文件路径
        output file name (default "host_collision_success_202304192245.txt")
  -r int    //速率限制
        rate limit (default:30) (default 30)
  -t int  //指定线程数
        Number of threads(default:10) (default 10)
  -uf string    //站点url，格式如https://1.1.1.1或https://1.1.1.1:8443
        url file path
```

单独使用

```
$ ./hostCollision -df hosts.txt -uf urls.txt 
```

对于url文件的生成，推荐下本人的方法：

1.首先通过各种方式收集子域名

2.通过https://github.com/alwaystest18/cdnChecker 来筛选未使用cdn的ip地址

3.通过https://github.com/projectdiscovery/mapcidr 直接生成ip段

4.通过https://github.com/projectdiscovery/naabu 对ip段进行常见web端口扫描

5.通过https://github.com/projectdiscovery/httpx 检测存活站点，结果文件可直接用于本程序uf参数使用

**本程序定位就是仅做host碰撞功能，因此强烈推荐对于已知的目标ip段使用naabu扫描端口+httpx验证存活站点后再进行host碰撞，可大大节省时间**

## 常见问题

- 目前已知的误报情况有哪些

​       答：有些站点对同一个host的两次请求也会返回完全不同结果，如：（一次302，一次403），推测为负载配置问题