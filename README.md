此项目不再更新，请移步至 https://github.com/qq906907952/go_proxy2

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

    "Udp_timeout":60,                    //udp超时时间
    "Ulimit":1024000,                    //linux最大打开文件数(最大打开连接数)，取值范围0-1048576

    }


服务端
-------
任意linux系统即可
修改目录下的go_proxy.json配置文件

    "Server": {
    "Turn": true,                     //服务端设置为true，注意不要和client同时设置为true
    "Port":[                          //监听端口列表，可监听多个端口
      {
        "Tls": {
                  "Turn":true,                                       //是否用tls协议传送数据 
                  "Tcp_encrypt":false,                              //tcp封装tls之前是否加密
                  "Server_cert_path":"cert/serv/server.crt",        //服务器证书路径
                  "Server_private_key_path":"cert/serv/server.key", //服务器私钥路径
                  "Client_cert_paths":[                             //客户端证书路径 只有添加证书的客户端才能正常连接
                    "cert/client/client.crt",
                    "cert/client/client.crt"
                  ]
                },
      
        "Listen_port":9999,              //监听的端口
        "Enc_method": "aes-256-cfb",     //加密方式，仅支持chacha20和aes-256-cfb
        "Password": ""                   //密码，必须为32个字符
      },

      {
         "Tls": {
                  "Turn":false
                },
      
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
            "Server_addr": "0.0.0.0",         //服务端地址,开启tls情况下要与证书的地址一致
            "Server_port": 9999,              //服务端端口
            "Enc_method": "chacha20",         //加密方式 仅支持chacha20和aes-256-cfb
            "Password": "",                   //密码 必须为32字节
            "Dns_addr":"8.8.8.8",             //dns地址
            "Dns_port":53,                    //dns端口
            "Dns_req_proto":"tcp",            //dns请求使用协议(tcp或udp，如果是tcp则请求为udp->tcp->udp)
            "Domain_cache_time":600           //dns缓存时间 单位秒 <=0不缓存  
            "Tls":{
                  "Turn":true,                            //是否用tls协议传送数据  需要与服务端一致
                  "Tcp_encrypt":false,                    //tcp封装tls之前是否加密 需要与服务端一致
                  "Root_cert_path":"cert/serv/root.crt",  //服务端根证书路径
                  "Client_cert":[                         //客户端证书及私钥路径 多个则每个连接随机选择一个
                    {
                      "Cert":"cert/client/client.crt",        //证书
                      "Private_key":"cert/client/client.key"  //私钥
                    }
                  
            
                  ]
                }
          }


目录下的dnsmasq-china-list用于排除国内域名，可以自行添加，格式：server=/域名/地址。china_ipv4为中国大陆ip段，用于排除国内ip。

dnsmasq-china-list项目地址：https://github.com/felixonmars/dnsmasq-china-list

在文件目录下下执行         ./go_proxy_macos go_proxy.json
或者需要后台运行,执行 nohup ./go_proxy_maxos go_proxy.json > /dev/null &

然后在系统代理或者一些浏览器插件上http代理设置为对应ip和端口



客户端和服务端时间
-------
请确保服务端与客户端时间正确,时间差不能超过一分钟。


关于证书
-------
开启tls会进行双向校验，因此需要生成服务端与客户端的私钥与自签证书。

服务端需要自身证书与私钥，并添加客户端的证书作为校验。

客户端需要自身证书与私钥，并添加服务端的根证书信任。

cert目录下包含生成证书的脚本。

切到cert/serv目录下修改cert/serv/serv.cnf 中 alt_names.IP.1 改为服务器ip 或者 alt_names.NDS.1改为服务器域名（macos 必须使用域名，没有域名在要hosts文件配置），
这里的值要与Client.Server_addr一致

执行 bash create_serv_crt.sh 生成证书与私钥，其中root.crt是根证书，server.crt 和 server.key 是服务器证书与私钥

切到cert/client目录下 执行 bash create_cli_crt.sh 生成单个客户端证书与私钥

bash create_cli_crt.sh ${n}  批量生成 ${n}为整数

