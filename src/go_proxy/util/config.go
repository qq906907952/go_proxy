package util

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"crypto/tls"
	"crypto/x509"
)

var Config config

var Group sync.WaitGroup

type config struct {
	Ulimit         uint64
	Connection_log bool
	Udp_timeout    int64
	Client struct {
		Tls struct {
			Turn           bool
			Tcp_encrypt    bool
			Root_cert_path string
			Client_cert []struct {
				Cert        string
				Private_key string
			}
		}

		Ipv6          bool
		Local_proxy   bool
		Local_addr    string
		Local_port    int
		Server_addr   string
		Server_port   int
		Enc_method    string
		Password      string
		Dns_addr      string
		Dns_port      int
		Dns_req_proto string
		Udp_checksum  bool
		Domain_cache_time int64
	}

	Server struct {
		Turn bool
		Port [] struct {
			Tls struct {
				Turn                    bool
				Tcp_encrypt             bool
				Server_cert_path        string
				Server_private_key_path string
				Client_cert_paths       []string
			}
			Listen_port int
			Enc_method  string
			Password    string
		}
	}
}

func init() {
	if len(os.Args) < 2 {
		fmt.Println("useage:go_proxy config_file_path")
		os.Exit(1)
	}
	file, err := os.Open(os.Args[1])

	if err != nil {
		log.Fatal(err)
	}

	b, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}

	if jerr := json.Unmarshal(b, &Config); jerr != nil {
		log.Fatal(jerr)
	}


	if Config.Client.Dns_req_proto != "tcp" && Config.Client.Dns_req_proto != "udp" {
		log.Fatal("dns request protocol is not support")
	}
	if net.ParseIP(Config.Client.Local_addr) == nil {
		log.Fatal("local address seem invalid ")
	}
	Dns_address = &net.UDPAddr{
		IP:   net.ParseIP(Config.Client.Dns_addr),
		Port: Config.Client.Dns_port,
		Zone: "",
	}
	if Dns_address.IP == nil {
		log.Fatal("Dns_addr illegal")
	}
	china_ipv4_list, err := os.Open("china_ipv4")
	if err != nil {
		Print_log("warnning open china_ipv4 file fail : " + err.Error())
	} else {
		reader := bufio.NewReader(china_ipv4_list)
		for {
			line, _, err := reader.ReadLine()
			if err != nil {
				if err == io.EOF {
					break
				} else {
					log.Fatal(err)
				}
			} else {
				if len(line) == 0 {
					continue
				}
				ip_mask := strings.Split(string(line), "/")
				if len(ip_mask) != 2 {
					Print_log("warnning : parse china_ipv4  encounter error : %s ", "format incorrect , correct format : ip/mast")
				}
				ipint, err := Ipv4str2int(ip_mask[0])
				if err != nil {
					Print_log("warnning : parse china_ipv4 ip at %s encounter error : %s ", string(line), err.Error())
					continue
				}

				mask, err := strconv.Atoi(ip_mask[1])
				if err != nil {
					Print_log("warnning : parse china_ipv4 port at %s encounter error : %s", string(line), err.Error())
					continue
				}

				china_ipv4[ipint] = mask
			}
		}

	}


	cn_domain,err:=os.Open("dnsmasq-china-list")
	if err!=nil{
		Print_log("warnning open dnsmasq-china-list file fail : " + err.Error())
	}else{
		r:=bufio.NewReader(cn_domain)
		for {
			line, _, err :=r.ReadLine()
			if err != nil {
				if err == io.EOF {
					break
				} else {
					log.Fatal(err)
				}
			}else{
				if len(line) == 0 {
					continue
				}
				s:=strings.Split(string(line),"/")
				if len(s)!=3{
					Print_log("warnning : parse dnsmasq-china-list  encounter error : %s ", "format incorrect , correct format : server=/${domain}/${dns address}")
					continue
				}
				domain_map.Store(s[1],nil)
			}
		}


	}

	if Config.Udp_timeout == 0 {
		Config.Udp_timeout = 30
	}

	if Config.Client.Local_proxy {
		Config.Client.Server_addr = strings.Trim(Config.Client.Server_addr, "")
		server_name:=Config.Client.Server_addr
		if net.ParseIP(Config.Client.Server_addr) == nil {
			domain := Config.Client.Server_addr
			ns, err := net.LookupIP(domain)
			if err != nil {
				log.Fatal(err)
			}
			Config.Client.Server_addr = ns[0].String()
			fmt.Printf("remote server %s,ip parse:%s:%d\r\n", domain, Config.Client.Server_addr, Config.Client.Server_port)

		} else {
			fmt.Printf("remote server %s:%d\r\n", Config.Client.Server_addr, Config.Client.Server_port)
		}
		if Config.Client.Tls.Turn {

			if len(Config.Client.Tls.Client_cert) == 0 {
				log.Fatal("Client_cert list can not null")
			}
			cert_pool := x509.NewCertPool()
			root_cert, err := ioutil.ReadFile(Config.Client.Tls.Root_cert_path)
			if err != nil {
				log.Fatal("load root cert fail : " + err.Error())
			}
			cert_pool.AppendCertsFromPEM(root_cert)
			client_tls_conf = &tls.Config{
				RootCAs:    cert_pool,
				ServerName: server_name,
			}

			for _, v := range Config.Client.Tls.Client_cert {
				cert, err := tls.LoadX509KeyPair(v.Cert, v.Private_key)
				if err != nil {
					log.Fatal("load client cert or private key fail : " + err.Error())
				}
				client_certs = append(client_certs, cert)
			}
		}

	}

}
