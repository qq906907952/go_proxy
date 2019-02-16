轻量级代理
======
纯go实现的基于http，socks5代理和基于iptables搭建全局智能翻墙环境

安装
-------
git clone https://github.com/qq906907952/go_proxy.git

目录下的go_proxy是linux x86-64 的可执行文件，如果需要其他平台可以自行编译。


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
            "Turn":false,                     //本地代理设置为false
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

在文件目录下下执行         ./go_proxy go_proxy.json
或者需要后台运行,执行 nohup ./go_proxy go_proxy.json > /dev/null &

然后在系统代理或者一些浏览器插件上http代理设置为对应ip和端口


客户端 linux透明代理 仅支持ipv4 
------
一般来说，作为路由至少要有两块网卡，可以是虚拟机也可以是树梅派之类。假设eth0为连接公网接口，br0为局域网接口,ip为192.168.1.1。
首先确保linux内核不低于2.6且安装了dnsmasq，iptables，ipset，且通过br0接口的机器能正常访问公网

通常，linux做路由器要打开ip转发：

编辑/etc/sysctl.conf
添加一行

net.ipv4.ip_forward=1

命令行执行

sysctl -p

然后iptables设置：

iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

这样连接到br0的机器应该能访问公网了。


修改go_proxy.json

    "Client":{
        "Turn_on":true,                    //设置为true
        "Ipv6":false,                     //
        "Local_proxy"：false，              //设置为false
        "Local_addr":"0.0.0.0",            //本地监听地址，一般为0.0.0.0或127.0.0.1
        "Local_port": 9999,                //本地监听端口
        "Server_addr": "0.0.0.0",          //服务端地址，开启tls情况下要与证书的地址一致
        "Server_port": 9999,               //服务端端口
        "Enc_method": "chacha20",          //加密方式 仅支持chacha20和aes-256-cfb
        "Password": "",                    //密码 必须为32字节
        "Dns_addr":"8.8.8.8:53",           //dns地址
        "Dns_req_proto":"tcp",             //无意义
        "Domain_cache_time":600,            //无意义
        
        "Tls":{                             //参考本地代理
              "Turn":true,                            
              "Tcp_encrypt":false,                    
              "Root_cert_path":"cert/serv/root.crt",  
              "Client_cert":[                         
                {
                  "Cert":"cert/client/client_2.crt",        
                  "Private_key":"cert/client/client_2.key"  
                },
                {
                  "Cert":"cert/client/client_1.crt",
                  "Private_key":"cert/client/client_1.key"
                }
        
              ]
            }
        
        

      }

首先修改dnsmasq配置文件：

编辑/etc/dnsmasq.conf：

    取消no-resolv 和 bind-interfaces 注释
    
    取消listen-address注释 并修改为 listen-address=127.0.0.1,192.168.1.1    //192.168.1.1 为br0网关地址 这里一定不要绑定为0.0.0.0 
    
    在最后添加

    server=127.0.0.1#9999      //上游dns地址 9999修改为客户端监听的端口

    conf-dir=/etc/dnsmasq.d/   //dnsmasq规则文件的路径

复制dnsmasq-china-list到dnsmasq规则文件的路径。

dnsmasq-china-list项目地址：https://github.com/felixonmars/dnsmasq-china-list

在这列表中的域名都会使用指定地址解析，其他域名都会使用上游地址解析。可以自行添加，格式：server=/域名/dns地址。

局域网的主机dns地址设置为192.168.1.1,则可以实现国内域名白名单




添加中国ip到ipset中:

在go_proxy目录下执行(bash环境 不同shell语法不同)

    ipset create cn_ipv4 hash:net

    for line in `cat china_ipv4`; do ipset add cn_ipv4 $line; done;

添加局域网和服务端地址到ipset：

    ipset create local hash:net

    ipset add local 127.0.0.0/8

    ipset add local 192.168.0.0/16

    ipset add local 169.254.0.0/16

    ipset add local 172.16.0.0/12

    ipset add local 10.0.0.0/8

    ipset add local 99.99.99.99/32          //99.99.99.99换成服务端ip



创建新链:

    iptables -t nat -N GO_PROXY


局域网和服务端地址return,非中国ip重定向到本地：

    iptables -t nat -A GO_PROXY -p tcp -m set  --match-set local dst -j RETURN

    iptables -t nat -A GO_PROXY -p tcp -m set  --match-set cn_ipv4 dst -j RETURN

    iptables -t nat -A GO_PROXY -p tcp  -j REDIRECT --to 9999               //9999改成客户端本地监听的端口

    iptables -t nat -A PREROUTING -p tcp -j GO_PROXY

    iptables -t nat -A OUTPUT -p tcp -j GO_PROXY


udp中继：

    iptables -t mangle -N GO_PROXY

    iptables -t mangle -A GO_PROXY -p udp -m set  --match-set local dst -j RETURN

    iptables -t mangle -A GO_PROXY -p udp -m set  --match-set cn_ipv4  dst -j RETURN

    iptables -t mangle -A GO_PROXY -p udp -j TPROXY --on-port 9999 --tproxy-mark 0x1/0x1      //9999改成客户端本地监听的端口

    iptables -t mangle -A PREROUTING -p udp -j GO_PROXY

    ip rule add fwmark  0x1/0x1 table 100

    ip route add local default dev lo table 100

这样 所有路由到192.168.1.1的设备都会通过代理访问


客户端和服务端时间
-------
请确保服务端与客户端时间正确,时间差不能超过一分钟。

关于证书
-------
开启tls会进行双向校验，因此需要生成服务端与客户端的私钥与自签证书。

服务端需要自身证书与私钥，并添加客户端的证书作为校验。

客户端需要自身证书与私钥，并添加服务端的根证书信任。

cert目录下包含生成证书的脚本。

切到cert/serv目录下修改cert/serv/serv.cnf 中 alt_names.IP.1 改为服务器ip 或者dn.CN改为服务器域名，
这里的值要与Client.Server_addr一致

执行 bash create_serv_crt.sh 生成证书与私钥，其中root.crt是根证书，server.crt 和 server.key 是服务器证书与私钥

切到cert/client目录下 执行 bash create_cli_crt.sh 生成单个客户端证书与私钥

bash create_cli_crt.sh ${n}  批量生成 ${n}为整数



 