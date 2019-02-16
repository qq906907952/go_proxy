package go_client

import (
	"net"
	"go_proxy/util"
	"encoding/binary"
	"fmt"
	"log"
	"time"
)

func Start_TCPclient() {
	defer util.Group.Done()

	tcp_crypt := util.Get_crypt(util.Config.Client.Enc_method, util.Config.Client.Password)
	if util.Config.Client.Tls.Turn && !util.Config.Client.Tls.Tcp_encrypt {
		tcp_crypt = util.Get_none_crypt()
	}

	tcp_listen, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   net.ParseIP(util.Config.Client.Local_addr),
		Port: util.Config.Client.Local_port,
		Zone: "",
	})
	if err != nil {
		log.Fatal(err)

	}
	_l := fmt.Sprintf("tcp client listen on %s:%d,remote server %s:%d \r\ncrypt method:%s",
		util.Config.Client.Local_addr,
		util.Config.Client.Local_port,
		util.Config.Client.Server_addr,
		util.Config.Client.Server_port,
		tcp_crypt.String())

	util.Print_log(_l)
	fmt.Println(_l)

	for {
		tcp_con, err := tcp_listen.AcceptTCP()
		if err != nil {
			util.Print_log("tcp accept error " + err.Error())
			continue
		}

		go handle_con(tcp_con, tcp_crypt)

	}
}

func handle_con(con *net.TCPConn, crypt util.Crypt_interface) {

	defer func() {
		util.Handle_panic()
		util.Close_tcp(con)

	}()

	con.SetKeepAlive(true)
	con.SetKeepAlivePeriod(10 * time.Second)
	addr, err := util.Get_tcp_origin_dest(con)
	if err != nil {
		util.Print_log("tcp can not read the origin dest:" + err.Error())
		return
	}

	dest := addr.Multiaddr[2:8]

	if util.Config.Connection_log {
		_dest := &net.TCPAddr{
			IP:   dest[2:],
			Port: int(binary.BigEndian.Uint16(dest[:2])),
		}
		util.Print_log("connection log:%s connect to %s", con.RemoteAddr().String(), _dest.String())
	}

	//connect to  the proxy server
	remote, raw_socket, err := util.Connect_to_server(crypt, util.Tcp_conn, int(binary.BigEndian.Uint16(dest[:2])), dest[2:])
	if err != nil {
		util.Print_log("connection to remote error:" + err.Error())
		return
	}

	defer util.Close_tcp(raw_socket)

	util.Connection_loop(con, remote, crypt)

}
