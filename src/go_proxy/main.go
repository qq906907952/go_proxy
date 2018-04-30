package main

import (
	"go_proxy/util"
	"go_proxy/go_server"
	"go_proxy/local_proxy"
	"syscall"
	"go_proxy/go_client"
)

func main() {

	syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{
		Cur: util.Config.Ulimit,
		Max: util.Config.Ulimit,
	})

	if util.Config.Client.Turn {

		util.Group.Add(1)
		go go_client.Start_TCPclient()

		if util.Config.Udp_relay {
			util.Group.Add(1)
			go go_client.Start_UDPclien()
		}
	}

	if util.Config.Client.Local_proxy {

		util.Group.Add(1)
		go local_proxy.Start_local_proxy_client()
	}

	if util.Config.Server.Turn {

		for _, port := range util.Config.Server.Port {

			util.Group.Add(1)
			go go_server.Start_TCPserver(port.Listen_port, util.Get_crypt(port.Enc_method, port.Password))

			if util.Config.Udp_relay {

				util.Group.Add(1)
				go go_server.Start_UDPserver(port.Listen_port, util.Get_crypt(port.Enc_method, port.Password))
			}
		}

	}

	util.Group.Wait()

}
