轻量级代理
======
纯go实现的基于http，socks5代理和基于iptables搭建全局智能翻墙环境

安装
-------
git clone https://github.com/qq906907952/go_proxy.git
。

使用方法
======
修改文件目录下的go_proxy.json配置文件：
-------
    {

    "Udp_relay":true,                    //udp中继，必须打开

    "Ulimit":1024000,                    //linux最大打开文件数(最大打开连接数)，取值范围0-1048576

    }


服务端
-------
任意linux系统即可
修改目录下的go_proxy.json配置文件

    "Server": {
    "Turn": true,                     //服务端设置为true，注意不要和client同时设置为true
    "Port":[                             //监听端口列表，可监听多个端口
      {
        "Listen_port":9999,              //监听的端口
        "Enc_method": "chacha20",        //加密方式，仅支持chacha20和aes-256-cfb
        "Password": ""                   //密码，必须为32个字符
      },

      {
        "Listen_port":9998,
        "Enc_method": "chacha20",
        "Password": ""
      }
    ]

    }

在目录下下执行./go_proxy go_proxy.json
或者需要后台运行 nohup ./go_proxy go_proxy.json > /dev/null &

如无意外 netstat -apn | grep LISTEN 能看到go_proxy进程监听的端口


客户端 本地代理
------



如果仅需要本地代理那么修改go_proxy.json，支持http和socks5，socks5不支持udp,http不能代理ftp

    "Client":{
            "Ipv6":false,                     //是否尝试將域名解析ipv6地址 需要服务器支持ipv6
            "Local_proxy":true，              //本地代理设置位true，注意和上面一项不能同时位true。
            "Local_addr":"0.0.0.0",           //本地监听地址，一般为0.0.0.0
            "Local_port": 9999,               //本地代理监听端口
            "Server_addr": "0.0.0.0",         //服务端地址
            "Server_port": 9999,              //服务端端口
            "Enc_method": "chacha20",         //加密方式 仅支持chacha20和aes-256-cfb
            "Password": "",                   //密码 必须为32字节
            "Dns_addr":"8.8.8.8",             //dns地址
            "Dns_port":53,                    //dns端口
            "Dns_req_proto":"tcp"             //dns请求使用协议(tcp或udp，如果是tcp则请求为udp->tcp->udp)
          }


目录下的dnsmasq-china-list用于排除国内域名，可以自行添加，格式：server=/域名/地址。china_ipv4为中国大陆ip段，用于排除国内ip。

dnsmasq-china-list项目地址：https://github.com/felixonmars/dnsmasq-china-list

在文件目录下下执行         ./go_proxy_macos go_proxy.json
或者需要后台运行,执行 nohup ./go_proxy_maxos go_proxy.json > /dev/null &

然后在系统代理或者一些浏览器插件上http代理设置为对应ip和端口



客户端和服务端时间
-------
请确保服务端与客户端时间正确,时间差不能超过一分钟。
