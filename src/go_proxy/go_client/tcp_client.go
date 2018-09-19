package go_client

import (
	"net"
	"go_proxy/util"
	"strconv"
	"encoding/binary"
	"fmt"
	"log"
	"time"
)

var crypt util.Crypt_interface

func Start_TCPclient() {
	defer util.Group.Done()
	crypt = util.Get_crypt(util.Config.Client.Enc_method, util.Config.Client.Password)

	tcp_listen, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   net.ParseIP(util.Config.Client.Local_addr),
		Port: util.Config.Client.Local_port,
		Zone: "",
	})
	if err != nil {
		log.Fatal(err)

	}

	util.Logger.Println("client listen on " + util.Config.Client.Local_addr + ":" + strconv.Itoa(util.Config.Client.Local_port) + " remote server " + util.Config.Client.Server_addr + ":" + strconv.Itoa(util.Config.Client.Server_port))
	fmt.Println("client listen on " + util.Config.Client.Local_addr + ":" + strconv.Itoa(util.Config.Client.Local_port) + " remote server " + util.Config.Client.Server_addr + ":" + strconv.Itoa(util.Config.Client.Server_port))

	for {
		tcp_con, err := tcp_listen.AcceptTCP()
		if err != nil {
			util.Logger.Println("tcp accept error " + err.Error())
			continue
		}

		go handle_con(tcp_con, crypt)

	}
}

func handle_con(con *net.TCPConn, crypt util.Crypt_interface) {

	defer util.Handle_panic()

	defer con.Close()
	con.SetKeepAlive(true)
	con.SetKeepAlivePeriod(10*time.Second)
	addr, err := util.Get_tcp_origin_dest(con)
	if err != nil {
		util.Logger.Println("tcp can not read the origin dest:" + err.Error())
		return
	}

	dest := addr.Multiaddr[2:8]



	if util.Config.Connection_log{
		_dest := &net.TCPAddr{
			IP:   dest[2:],
			Port: int(binary.BigEndian.Uint16(dest[:2])),
		}
		util.Logger.Printf("connection log:%s connect to %s" ,con.RemoteAddr().String(),_dest.String())
	}

	//connect to  the proxy server
	remote, err := util.Connect_to_server(crypt,util.Tcp_conn, int(binary.BigEndian.Uint16(dest[:2])), dest[2:])
	if err != nil {
		util.Logger.Println("connection to remote error:"+err.Error())
		return
	}
	defer remote.Close()

	util.Connection_loop(con, remote, crypt)

}
