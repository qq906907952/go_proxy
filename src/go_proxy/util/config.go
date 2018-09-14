package util

import (
	"log"
	"encoding/json"
	"io/ioutil"
	"os"
	"net"
	"fmt"
	"sync"
	"bufio"
	"io"
	"strings"
	"strconv"
)

var Config config
//var Sign = make(chan bool)

var Group sync.WaitGroup

type config struct {
	Udp_relay bool
	Ulimit    uint64
	Connection_log bool
	Client struct {
		Turn          bool
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
	}

	Server struct {
		Turn bool
		Port [] struct {
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

	if Config.Client.Turn && Config.Server.Turn {
		log.Fatal("server and client can not be turn on in the same machine")
	}

	if Config.Client.Turn && Config.Client.Local_proxy {
		log.Fatal("client and http_proxy can not be turn on in the same machine")
	}
	if Config.Client.Dns_req_proto != "tcp" && Config.Client.Dns_req_proto != "udp" {
		log.Fatal("dns request protocol is not support")
	}
	if net.ParseIP(Config.Client.Local_addr)==nil  {
		log.Fatal("local address seem invalid ")
	}
	Dns_address = &net.UDPAddr{
		IP:   net.ParseIP(Config.Client.Dns_addr),
		Port: Config.Client.Dns_port,
		Zone: "",
	}
	if Dns_address.IP==nil{
		panic("Dns_addr illegal")
	}
	china_ipv4_list, err := os.Open("china_ipv4")
	if err != nil {
		return
	}

	reader := bufio.NewReader(china_ipv4_list)
	for {
		line, _, err := reader.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			} else {
				log.Fatal(err)
			}
		}else {
			if len(line) == 0 {
				continue
			}
			ip_mask := strings.Split(string(line), "/")
			mask, err := strconv.Atoi(ip_mask[1])
			if err != nil {
				continue
			}

			ipint, err := Ipv4str2int(ip_mask[0])
			if err!=nil{
				continue
			}
			china_ipv4[ipint]=mask
		}
	}
	if net.ParseIP(Config.Client.Server_addr)==nil{
		domain:=Config.Client.Server_addr
		ns,err:=net.LookupIP(domain)
		if err!=nil{
			panic(err)
		}
		Config.Client.Server_addr=ns[0].String()
		fmt.Printf("remote server %s,ip parse:%s:%d\r\n",domain,Config.Client.Server_addr,Config.Client.Server_port)

	}else{
		fmt.Printf("remote server %s:%d\r\n",Config.Client.Server_addr,Config.Client.Server_port)
	}



}
