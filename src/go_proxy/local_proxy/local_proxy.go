package local_proxy

import (
	"net"
	"strconv"
	"strings"
	"go_proxy/util"
	"bufio"
	"bytes"
	"log"
	"fmt"
	"io"
	"net/http"
	"time"
)

var crypt util.Crypt_interface

func Start_local_proxy_client() {
	defer util.Group.Done()

	crypt = util.Get_crypt(util.Config.Client.Enc_method, util.Config.Client.Password)
	lcoal_listen, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   net.ParseIP(util.Config.Client.Local_addr),
		Port: util.Config.Client.Local_port,
		Zone: "",
	})

	if err != nil {
		log.Fatal(err)

	}

	fmt.Println("local_proxy listen on " + util.Config.Client.Local_addr + ":" + strconv.Itoa(util.Config.Client.Local_port))
	util.Logger.Println("local_proxy listen on " + util.Config.Client.Local_addr + ":" + strconv.Itoa(util.Config.Client.Local_port))

	for {
		local, err := lcoal_listen.AcceptTCP()
		if err != nil {
			util.Logger.Println("tcp accept error " + err.Error())
			continue
		}
		local.SetKeepAlive(true)
		local.SetKeepAlivePeriod(10*time.Second)
		go func() {

			defer local.Close()
			defer util.Handle_panic()
			recv := make([]byte, 1)
			_, err = io.ReadFull(local, recv)

			if err != nil {
				return
			}

			//proxy decide
			if recv[0] == 5  {

				Handle_sock5_proxy(local)
			} else {
				b, o, err := util.Read_at_least_byte(local, []byte("\r\n\r\n"))

				if b == nil || err != nil {
					return
				}

				Handle_http_proxy(local, bytes.Join([][]byte{recv, b, o}, nil))
			}
		}()

	}
}

func Handle_http_proxy(local *net.TCPConn, recv []byte) {

	header, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(recv)))

	if err != nil {
		return
	}

	if strings.ToUpper(header.Method) == "CONNECT" {

		Handle_HTTPS(local, header.Host)

	} else {
		host := header.Host
		var dest_port int
		var url string
		var err error

		_host := strings.Split(host, ":")
		switch len(_host) {
		case 1:
			url = host
			dest_port = 80
		case 2:
			url = _host[0]
			dest_port, err = strconv.Atoi(_host[1])
			if err != nil {
				return
			}
		default:
			return

		}

		recv = convert_to_close(recv)
		index := bytes.Index(recv, []byte("http://"))

		if index != -1 {
			Handle_HTTP(local, url, dest_port, bytes.Join([][]byte{recv[:index], recv[index+len([]byte("http://"))+len([]byte(host)):]}, nil))
		} else {
			Handle_HTTP(local, url, dest_port, recv)
		}
	}

}

func Handle_sock5_proxy(con *net.TCPConn) {
	_b:=make([]byte,1)
	if _,err:=con.Read(_b);err!=nil{
		return
	}
	_b,err:=util.Read_tcp_data(con,int(_b[0]))
	if err!=nil{
		return
	}
	for _,v:=range _b{
		if v==0{
			if _, err := con.Write([]byte{5, 0}); err != nil {
				return
			}

			recv, err := util.Read_tcp_data(con, 4)

			if err != nil {
				return
			}

			if recv[1] == 1 {
				handle_socks5_tcp(con, recv)
			} else if recv[1] == 3 {
				handle_socks5_udp(con, recv)
			}
		}
	}

}

func convert_to_close(recv []byte) ([]byte) {
	recv = []byte(strings.Replace(string(recv), "keep-alive", "close", -1))
	recv = []byte(strings.Replace(string(recv), "Keep-Alive", "close", -1))
	return recv
}
