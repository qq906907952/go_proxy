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

	dest, request_type, err := handshake(con, crypt)

	if err != nil {

		return
	}

	//check dns request
	dec_data, err := crypt.Read(con)
	if err != nil {

		return
	}

	if request_type == util.Udp_conn {

		ns, err := net.DialUDP("udp", nil, &net.UDPAddr{
			IP:   dest.IP,
			Port: dest.Port,
			Zone: "",
		})
		if err != nil {
			util.Logger.Println("cant not connect from " + con.RemoteAddr().String() + " to " + dest.IP.String() + ":" + strconv.Itoa(dest.Port) + " " + err.Error())
			return
		}
		defer ns.Close()
		if _, err := ns.Write(dec_data); err != nil {
			return
		}
		go func() {
			defer ns.Close()
			defer con.Close()
			answer := make([]byte, util.Udp_recv_buff)
			for {
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
			dec_data, err := crypt.Read(con)
			if err != nil {
				return
			}
			if _, err := ns.Write(dec_data); err != nil {
				return
			}

		}

	} else if request_type == util.Tcp_conn {

		target, err := net.DialTCP("tcp", nil, dest)
		if err != nil {
			util.Logger.Println("cant not connect from " + con.RemoteAddr().String() + " to " + dest.IP.String() + ":" + strconv.Itoa(dest.Port) + " " + err.Error())
			return
		}
		defer target.Close()

		if _, err := target.Write(dec_data); err != nil {

			return
		}

		util.Connection_loop(target, con, crypt)
	} else {
		util.Logger.Println("unknow connect type from " + con.RemoteAddr().String() + " to " + dest.IP.String() + ":" + strconv.Itoa(dest.Port))
		return
	}

}

func handshake(con *net.TCPConn, crypt util.Crypt_interface) (*net.TCPAddr, int, error) {
	data, err := crypt.Read(con)
	if len(data) < 15 || (data[8] != 1 && data[8] != 0 ) || int(data[9]) > len(data[10:]) {
		util.Logger.Println("len error:data len too short ")
		return nil, 0, errors.New("len error")
	}
	timestamp := binary.BigEndian.Uint64(data[:8])
	if err != nil || time.Now().Unix()-int64(timestamp) > 60 {
		if err != nil {
			return nil, 0, err
		} else {
			util.Logger.Println("time error : time is pass than 60 seconds from " + con.RemoteAddr().String())
			return nil, 0, errors.New("time is pass than 60 seconds ")
		}
	}

	dest_addr := data[10:10+data[9]]

	dest := &net.TCPAddr{
		IP:   dest_addr[2:],
		Port: int(binary.BigEndian.Uint16(dest_addr[:2])),
		Zone: "",
	}
	request_type := int(data[8])

	return dest, request_type, nil

}
