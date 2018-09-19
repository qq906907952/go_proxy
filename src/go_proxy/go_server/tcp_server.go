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
)

func Start_TCPserver(port int, crypt util.Crypt_interface) {
	defer util.Group.Done()
	listen, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   nil,
		Port: port,
		Zone: "",
	})
	if err != nil {
		log.Fatal(err)

	}

	util.Logger.Println("TCP server listen on " + "0.0.0.0" + ":" + strconv.Itoa(port))
	fmt.Println("TCP server listen on " + "0.0.0.0" + ":" + strconv.Itoa(port))

	for {
		tcp_con, err := listen.AcceptTCP()
		if err != nil {
			util.Logger.Println("tcp accept error " + err.Error())
			continue
		}

		go handle_con(tcp_con, crypt)

	}
}

func handle_con(con *net.TCPConn, crypt util.Crypt_interface) {
	var err error
	defer util.Handle_panic()
	defer con.Close()
	con.SetKeepAlive(true)
	con.SetKeepAlivePeriod(10*time.Second)

	dest, request_type, err := handshake(con, crypt)

	if err != nil {
		util.Logger.Println("tcp handshake error:"+err.Error())
		return
	}


	if request_type == util.Udp_conn {
		ns, err := net.DialUDP("udp", nil, &net.UDPAddr{
			IP:   dest.IP,
			Port: dest.Port,
			Zone: "",
		})
		if err != nil {
			util.Logger.Println("can not dial udp from " + con.RemoteAddr().String() + " to " + dest.IP.String() + ":" + strconv.Itoa(dest.Port) + " " + err.Error())
			return
		}
		defer ns.Close()

		go func() {
			defer ns.Close()
			defer con.Close()
			answer := make([]byte, util.Udp_recv_buff)
			for {
				if err:=ns.SetReadDeadline(time.Now().Add(time.Duration(util.Config.Udp_timeout)*time.Second));err!=nil{
					util.Logger.Println("set udp read deadline error" + err.Error())
					return
				}
				i, err := ns.Read(answer)
				if i > 0 {
					if err := crypt.Write(con, answer[:i]); err != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}()

		for {
			if err:=con.SetReadDeadline(time.Now().Add(time.Duration(util.Config.Udp_timeout)*time.Second));err!=nil{
				util.Logger.Println("set udp read deadline error" + err.Error())
				return
			}
			dec_data, err := crypt.Read(con)
			if err != nil {
				return
			}
			if dest.Port==53 && util.Config.Connection_log {
				go func(){
					domain:=util.Get_domain_name_from_request(dec_data)
					if domain!=""{
						util.Logger.Printf("connection log:%s query domain name %s" ,con.RemoteAddr().String(), domain)
					}
				}()
			}

			if _, err := ns.Write(dec_data); err != nil {
				return
			}

		}

	} else if request_type == util.Tcp_conn {

		target, err := net.DialTCP("tcp", nil, dest)
		if err != nil {
			util.Logger.Println("tcp can not connect from " + con.RemoteAddr().String() + " to " + dest.IP.String() + ":" + strconv.Itoa(dest.Port) + " " + err.Error())
			return
		}
		defer target.Close()
		target.SetKeepAlive(true)
		target.SetKeepAlivePeriod(10*time.Second)
		util.Connection_loop(target, con, crypt)
	} else {
		util.Logger.Println("unknow connect type from " + con.RemoteAddr().String() + " to " + dest.IP.String() + ":" + strconv.Itoa(dest.Port))
		return
	}

}

func handshake(con *net.TCPConn, crypt util.Crypt_interface) (*net.TCPAddr, int, error) {
	data, err := crypt.Read(con)
	if len(data) < 15 || (data[8] != 1 && data[8] != 0 ) || int(data[9]) > len(data[10:]) {
		util.Logger.Println("len error:data len illegal ")
		return nil, 0, errors.New("len error")
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
		util.Logger.Printf("connection log:%s connect to %s" ,con.RemoteAddr().String(),dest.String())
	}
	request_type := int(data[8])

	return dest, request_type, nil

}
