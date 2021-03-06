package go_server

import (
	"net"
	"go_proxy/util"
	"strconv"
	"fmt"
	"log"
	"encoding/binary"
	"time"
	"errors"
	"crypto/tls"
)

func Start_TCPserver(port int, crypt util.Crypt_interface, tls_conf *tls.Config) {
	defer util.Group.Done()
	listen, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   nil,
		Port: port,
		Zone: "",
	})
	if err != nil {
		log.Fatal(err)

	}
	_l:=fmt.Sprintf("TCP server listen on %s:%d crypt method:%s" , "0.0.0.0" , port,crypt.String())
	util.Print_log(_l)
	fmt.Println(_l)

	for {
		tcp_con, err := listen.AcceptTCP()
		if err != nil {
			util.Print_log("tcp accept error " + err.Error())
			continue
		}

		go handle_con(tcp_con, crypt,tls_conf)

	}


}

func handle_con(_con *net.TCPConn, crypt util.Crypt_interface,tls_conf *tls.Config) {
	var err error
	defer util.Handle_panic()

	defer util.Close_tcp(_con)
	_con.SetKeepAlive(true)
	_con.SetKeepAlivePeriod(10*time.Second)

	var con net.Conn
	if tls_conf!=nil{
		con=tls.Server(_con,tls_conf)
	}else{
		con=_con
	}


	dest, request_type, err := handshake(con, crypt)

	if err != nil {
		util.Print_log("tcp handshake error:"+err.Error())
		return
	}


	if request_type == util.Udp_conn {

		dec_data, err := crypt.Read(con)
		if err != nil {
			return
		}
		if dest.Port==53 && util.Config.Connection_log {
			go func(dec_data []byte){
				domain:=util.Get_domain_name_from_request(dec_data)
				if domain!="" && util.Config.Connection_log{
					util.Print_log("connection log:%s query domain name %s" ,con.RemoteAddr().String(), domain)
				}
			}(dec_data)
		}

		ns, err := net.DialUDP("udp", nil, &net.UDPAddr{
			IP:   dest.IP,
			Port: dest.Port,
			Zone: "",
		})
		if err != nil {
			util.Print_log("can not dial udp from " + con.RemoteAddr().String() + " to " + dest.IP.String() + ":" + strconv.Itoa(dest.Port) + " " + err.Error())
			return
		}
		defer ns.Close()

		if _, err := ns.Write(dec_data); err != nil {
			return
		}

		if err:=ns.SetReadDeadline(time.Now().Add(time.Duration(util.Config.Udp_timeout)*time.Second));err!=nil{
			util.Print_log("set udp read deadline error" + err.Error())
			return
		}
		answer := make([]byte, util.Udp_recv_buff)
		i, err := ns.Read(answer)
		if i > 0 {
			if err := crypt.Write(con, answer[:i]); err != nil {
				util.Print_log("write to remote fail:" + err.Error())
				return
			}
		}
		if err != nil {
			return
		}

	} else if request_type == util.Tcp_conn {

		target, err := net.DialTCP("tcp", nil, dest)
		if err != nil {
			util.Print_log("tcp can not connect from " + con.RemoteAddr().String() + " to " + dest.IP.String() + ":" + strconv.Itoa(dest.Port) + " " + err.Error())
			return
		}
		defer util.Close_tcp(target)
		target.SetKeepAlive(true)
		target.SetKeepAlivePeriod(10*time.Second)
		util.Connection_loop(target, con, crypt)
	} else {
		util.Print_log("unknow connect type from " + con.RemoteAddr().String() + " to " + dest.IP.String() + ":" + strconv.Itoa(dest.Port))
		return
	}

}

func handshake(con net.Conn, crypt util.Crypt_interface) (*net.TCPAddr, int, error) {
	data, err := crypt.Read(con)
	if err!=nil{
		return nil,0,err
	}
	// timestamp(8 bytes) + type(udp or tcp) + dest addr len(1 byte) + dest port(2 bytes) + dest ip(4 or 16) + data
	if len(data) < 15 || (data[8] != 1 && data[8] != 0 ) || int(data[9]) > len(data[10:]) {
		return nil, 0, errors.New("len error,maybe enc method not correspond")
	}
	timestamp := binary.BigEndian.Uint64(data[:8])
	if err != nil || time.Now().Unix()-int64(timestamp) > 60 {
		if err != nil {
			return nil, 0, err
		} else {

			return nil, 0, errors.New("time was pass more than 60 seconds ")
		}
	}

	dest_addr := data[10:10+data[9]]
	if len(dest_addr[2:])!=4 &&  len(dest_addr[2:])!=16{
		return nil,0,errors.New("ip len error")
	}
	dest := &net.TCPAddr{
		IP:   dest_addr[2:],
		Port: int(binary.BigEndian.Uint16(dest_addr[:2])),
		Zone: "",
	}

	if util.Config.Connection_log{
		util.Print_log("connection log:%s connect to %s" ,con.RemoteAddr().String(),dest.String())
	}
	request_type := int(data[8])

	return dest, request_type, nil

}
