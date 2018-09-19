package go_server

import (
	"net"
	"strconv"
	"go_proxy/util"
	"encoding/binary"
	"fmt"
	"log"
	"sync"
	"time"
)

type udp_route struct {
	socket  *net.UDPConn
	send_to *net.UDPAddr
}

var (
	route_map = map[string]*udp_route{}
	lock      = sync.RWMutex{}
)

func Start_UDPserver(port int, crypt util.Crypt_interface) {
	defer util.Group.Done()
	listen, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   nil,
		Port: port,
		Zone: "",
	})

	if err != nil {
		log.Fatal(err)

	}
	defer listen.Close()

	util.Logger.Println("UDP server listen on " + "0.0.0.0" + ":" + strconv.Itoa(port))
	fmt.Println("UDP server listen on " + "0.0.0.0" + ":" + strconv.Itoa(port))

	for {

		recv_data := make([]byte, util.Udp_recv_buff)
		i, addr, err := listen.ReadFromUDP(recv_data)

		if err != nil {
			util.Logger.Println("udp recv err:" + err.Error())
			continue
		}

		go handle_udp_data(addr, recv_data[:i], listen, crypt)

	}
}

func handle_udp_data(udp_addr *net.UDPAddr, data []byte, server *net.UDPConn, crypt util.Crypt_interface) {

	defer util.Handle_panic()

	dec_data, err := crypt.Decrypt(data)

	if err != nil {
		util.Logger.Println("udp:can not decrypt data from " + udp_addr.String() + " : " + err.Error())
		return
	}
	dest_addr_len := dec_data[0]

	if dest_addr_len < 6 || len(dec_data) < int(dest_addr_len)+14 {
		util.Logger.Println("udp:recv data len error from " + udp_addr.String() + " : " + err.Error())
		return
	}
	origin_addr_len := dec_data[int(dest_addr_len)+1]
	if origin_addr_len < 6 || len(dec_data) < int(origin_addr_len+dest_addr_len)+2 {
		util.Logger.Println("udp:recv data len error from " + udp_addr.String() + " : " + err.Error())
		return
	}

	dest_port := binary.BigEndian.Uint16(dec_data[1:3])
	dest_ip := dec_data[3 : dest_addr_len+1]
	origin_port := binary.BigEndian.Uint16(dec_data[dest_addr_len+2 : dest_addr_len+4])
	origin_ip := dec_data[dest_addr_len+4 : dest_addr_len+4+origin_addr_len-2]

	real_data := dec_data[dest_addr_len+origin_addr_len+2:]

	if dest_port == 53 && util.Config.Connection_log{
		go func(){
			domain:=util.Get_domain_name_from_request(real_data)
			if domain!=""{
				util.Logger.Printf("connection log:%s query domain name %s" ,udp_addr.String(), domain)
			}
		}()
	}

	origin_addr := net.UDPAddr{
		IP:   origin_ip,
		Port: int(origin_port),
	}

	dest_addr := &net.UDPAddr{
		IP:   dest_ip,
		Port: int(dest_port),
	}

	var
	(
		route *udp_route
		ok    bool
	)



	lock.RLock()
	route, ok = route_map[origin_addr.String()+":"+udp_addr.IP.String()]
	lock.RUnlock()


	if !ok {
		con, err := net.ListenUDP("udp", nil)
		if err != nil {
			util.Logger.Println("dial udp error:" + err.Error())
			return
		}

		route = &udp_route{
			socket:  con,
			send_to: udp_addr,
		}



		lock.Lock()
		route_map[origin_addr.String()+":"+udp_addr.IP.String()] = route
		lock.Unlock()
		defer func(){
			lock.Lock()
			delete(route_map,origin_addr.String()+":"+udp_addr.IP.String())
			lock.Unlock()
			con.Close()
		}()

	} else {
		route.send_to = udp_addr
	}


	route.socket.WriteTo(real_data, dest_addr)
	if !ok{
		recv := make([]byte, util.Udp_recv_buff)
		for {

			if err := route.socket.SetReadDeadline(time.Now().Add(time.Duration(util.Config.Udp_timeout) * time.Second)); err != nil {
				util.Logger.Println("set udp read deadline error" + err.Error())
				return
			}

			i, err := route.socket.Read(recv)

			if i > 0 {
				server.WriteToUDP(crypt.Encrypt(recv[:i]), route.send_to)
			}

			if err != nil {
				return
			}
		}
	}


}
