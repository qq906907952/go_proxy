package util

import (
	"log"
	"encoding/json"
	"io/ioutil"
	"os"
	"net"
	"fmt"
	"sync"
)

var Config config
//var Sign = make(chan bool)

var Group sync.WaitGroup

type config struct {
	Udp_relay bool
	Ulimit    uint64

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

	Dns_address = &net.UDPAddr{
		IP:   net.ParseIP(Config.Client.Dns_addr),
		Port: Config.Client.Dns_port,
		Zone: "",
	}


}
