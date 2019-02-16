package local_proxy

import (
	"go_proxy/util"
	"net"
	"io"
	"fmt"
	"time"

)

func handle_connection(local *net.TCPConn, ip *net.IPAddr, dest_port int, prefix_data []byte, ack_data []byte, is_cn bool) {
	var remote net.Conn
	var err error

	if is_cn {

		remote, err = net.DialTCP("tcp", nil, &net.TCPAddr{
			IP:   ip.IP,
			Port: dest_port,
			Zone: "",
		})

		if err != nil {
			util.Print_log(fmt.Sprintf("can not connect to %s:%s",ip.String(),err.Error()))
			return
		}
		remote.(*net.TCPConn).SetKeepAlive(true)
		remote.(*net.TCPConn).SetKeepAlivePeriod(10*time.Second)
		defer util.Close_tcp(remote.(*net.TCPConn))
	} else {
		var raw_socket *net.TCPConn
		remote,raw_socket, err = util.Connect_to_server(tcp_crypt, util.Tcp_conn,dest_port, ip.IP)

		if err != nil {
			util.Print_log("can not connect to server : " + err.Error())
			return
		}
		defer util.Close_tcp(raw_socket)
	}



	if prefix_data != nil {
		if is_cn {
			if _, werr := remote.Write(prefix_data); werr != nil {
				return
			}
		} else {

			err := tcp_crypt.Write(remote, prefix_data)
			if err != nil {
				return
			}
		}
	}

	if ack_data != nil {
		if _, werr := local.Write(ack_data); werr != nil {
			return
		}
	}

	//loop
	if is_cn {

		go func() {
			defer util.Close_tcp(local)
			defer util.Close_tcp(remote.(*net.TCPConn))
			io.Copy(local, remote)
		}()

		io.Copy(remote, local)


	} else {

		util.Connection_loop(local, remote, tcp_crypt)
	}

}
