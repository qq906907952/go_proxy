package go_server

import (
	"net"
	"strconv"
	"go_proxy/util"
	"encoding/binary"
	"fmt"
	"log"
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
			continue
		}

		go handle_udp_data(addr, recv_data[:i], listen, crypt)

	}
}

func handle_udp_data(udp_addr *net.UDPAddr, data []byte, server *net.UDPConn, crypt util.Crypt_interface) {

	defer util.Handle_panic()

	dec_data, err := crypt.Decrypt(data)

	if err != nil {

		util.Logger.Println("can not dec data from " + udp_addr.String() + " : " + err.Error())
		return
	}
	dest_addr_len := dec_data[0]
	if dest_addr_len < 6 || len(dec_data) < int(dest_addr_len)+4 {
		return
	}

	dest_port := binary.BigEndian.Uint16(dec_data[1:3])
	origin_port := binary.BigEndian.Uint16(dec_data[dest_addr_len+1:dest_addr_len+3])

	dest_addr := &net.UDPAddr{
		IP:   dec_data[3:dest_addr_len+1],
		Port: int(dest_port),
		Zone: "",
	}

	target, err := net.DialUDP("udp", &net.UDPAddr{
		IP:   nil,
		Port: int(origin_port),
		Zone: "",
	}, dest_addr)




	if err != nil {
		util.Logger.Println("udp can not connect to " + dest_addr.String() + ":" + err.Error())
		return
	}

	defer target.Close()

	if _, werr := target.Write(dec_data[dest_addr_len+3:]); werr != nil {

		return
	}

	//util.Logger.Println("udp  from " + udp_addr.IP.String() + " connected to " + target.RemoteAddr().String())

	recv := make([]byte, util.Udp_recv_buff)
	i, rerr := target.Read(recv)
	if rerr != nil {

		return
	}

	enc_data := crypt.Encrypt(recv[:i])

	if _, werr := server.WriteToUDP(enc_data, udp_addr); werr != nil {
		return
	}

}
