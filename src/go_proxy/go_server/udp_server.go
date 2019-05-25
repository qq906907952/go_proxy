package go_server

import (
	"net"
	"go_proxy/util"
	"encoding/binary"
	"fmt"
	"log"
	"sync"
	"time"
	"bytes"
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

	_l := fmt.Sprintf("UDP server listen on %s:%d  crypt method:%s", "0.0.0.0", port, crypt.String())
	util.Print_log(_l)
	fmt.Println(_l)

	for {

		recv_data := make([]byte, util.Udp_recv_buff)
		i, addr, err := listen.ReadFromUDP(recv_data)

		if err != nil {
			util.Print_log("udp recv err:" + err.Error())
			continue
		}

		go handle_udp_data(addr, recv_data[:i], listen, crypt)

	}
}

func handle_udp_data(udp_addr *net.UDPAddr, data []byte, server *net.UDPConn, crypt util.Crypt_interface) {

	defer util.Handle_panic()

	dec_data, err := crypt.Decrypt(data)

	if err != nil {
		util.Print_log("udp:can not decrypt data from " + udp_addr.String() + " : " + err.Error())
		return
	}
	dest_addr_len := dec_data[0]
	// dest addr len + dest port(2 bytes) + dest ip + lan addr len + lan port (2) + lan ip + data
	if dest_addr_len < 6 || len(dec_data) < int(dest_addr_len)+2 {
		util.Print_log("udp:recv data len error from " + udp_addr.String())
		return
	}
	origin_addr_len := dec_data[int(dest_addr_len)+1]
	if origin_addr_len < 6 || len(dec_data) < int(origin_addr_len)+int(dest_addr_len)+2 {
		util.Print_log("udp:recv data len error from " + udp_addr.String())
		return
	}

	dest_port := binary.BigEndian.Uint16(dec_data[1:3])
	dest_ip := dec_data[3: dest_addr_len+1]

	//lan ip and port
	origin_port_byte := dec_data[dest_addr_len+2: dest_addr_len+4]
	origin_port := binary.BigEndian.Uint16(origin_port_byte)
	origin_ip := dec_data[dest_addr_len+4: dest_addr_len+4+origin_addr_len-2]
	real_data := dec_data[dest_addr_len+origin_addr_len+2:]

	if dest_port == 53 && util.Config.Connection_log {
		go func() {
			domain := util.Get_domain_name_from_request(real_data)
			if domain != "" {
				util.Print_log("connection log:%s query domain name %s", udp_addr.String(), domain)
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
			util.Print_log("dial udp error:" + err.Error())
			return
		}

		route = &udp_route{
			socket:  con,
			send_to: udp_addr,
		}

		lock.Lock()
		route_map[origin_addr.String()+":"+udp_addr.IP.String()] = route
		lock.Unlock()
		defer func() {
			lock.Lock()
			delete(route_map, origin_addr.String()+":"+udp_addr.IP.String())
			lock.Unlock()
			con.Close()
		}()

	} else {
		route.send_to = udp_addr
	}

	route.socket.WriteTo(real_data, dest_addr)
	if !ok {

		for {

			if err := route.socket.SetReadDeadline(time.Now().Add(time.Duration(util.Config.Udp_timeout) * time.Second)); err != nil {
				util.Print_log("set udp read deadline error" + err.Error())
				return
			}
			recv := make([]byte, util.Udp_recv_buff)
			i, _from_addr, err := route.socket.ReadFrom(recv)
			if i > 0 {
				from_addr := _from_addr.(*net.UDPAddr)

				from_port := make([]byte, 2)
				binary.BigEndian.PutUint16(from_port, uint16(from_addr.Port))
				dest_b := []byte{}
				if from_addr.IP.To4() != nil {
					dest_b = bytes.Join([][]byte{from_port, from_addr.IP.To4()}, nil)

				} else {
					dest_b = bytes.Join([][]byte{from_port, from_addr.IP.To16()}, nil)
				}

				origin_b := bytes.Join([][]byte{origin_port_byte, origin_ip}, nil)
				//dest addr len + dest port (2) + dest ip(4 or 16) +
				//lan addr len + lan port(2 bytes) + lan ip(4 or 16 bytes) +
				//data
				server.WriteToUDP(crypt.Encrypt(bytes.Join([][]byte{
					{byte(len(dest_b))}, dest_b,
					{byte(len(origin_b))}, origin_b,
					recv[:i]}, nil)), route.send_to)

			}

			if err != nil {
				return
			}
		}
	}

}
