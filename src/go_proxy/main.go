package main

import (
	"go_proxy/util"
	"go_proxy/go_server"
	"go_proxy/local_proxy"
	"syscall"
	"go_proxy/go_client"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
)

func main() {

	syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{
		Cur: util.Config.Ulimit,
		Max: util.Config.Ulimit,
	})

	if util.Config.Client.Turn {

		util.Group.Add(2)
		go go_client.Start_TCPclient()
		go go_client.Start_UDPclien()

	}

	if util.Config.Client.Local_proxy {

		util.Group.Add(1)
		go local_proxy.Start_local_proxy_client()
	}

	if util.Config.Server.Turn {

		for _, port := range util.Config.Server.Port {
			if !port.Tls.Turn && port.Enc_method == "None" {
				log.Fatal("enc method must not none when tls disable")
			}
			var tls_conf *tls.Config
			tcp_crypt:=util.Get_crypt(port.Enc_method, port.Password)
			if port.Tls.Turn {

				if !port.Tls.Tcp_encrypt{
					tcp_crypt=util.Get_none_crypt()
				}

				if len(port.Tls.Client_cert_paths) == 0 {
					log.Fatal("client cert paths list can not null")
				}

				cert, err := tls.LoadX509KeyPair(port.Tls.Server_cert_path, port.Tls.Server_private_key_path)
				if err != nil {
					log.Fatal("load server cert and private key error:" + err.Error())
				}
				cli_cert := x509.NewCertPool()
				for _, v := range port.Tls.Client_cert_paths {
					b, err := ioutil.ReadFile(v)
					if err != nil {
						log.Fatal("load client cert fail : " + err.Error())
					}
					cli_cert.AppendCertsFromPEM(b)

				}
				tls_conf = &tls.Config{

					Certificates: []tls.Certificate{cert},
					ClientAuth:   tls.RequireAndVerifyClientCert,
					ClientCAs:    cli_cert,
				}
			}
			util.Group.Add(2)
			go go_server.Start_TCPserver(port.Listen_port, tcp_crypt, tls_conf)
			go go_server.Start_UDPserver(port.Listen_port, util.Get_crypt(port.Enc_method, port.Password))

		}

	}

	util.Group.Wait()

}
