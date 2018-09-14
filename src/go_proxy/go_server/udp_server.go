package go_server

import (
	"net"
	"strconv"
	"go_proxy/util"
	"encoding/binary"
	"fmt"
	"log"
	"syscall"
	"go_proxy/go_client"
	"os"
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
			util.Logger.Println("udp recv err:"+err.Error())
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
	if dest_addr_len < 6 || len(dec_data) < int(dest_addr_len)+4 {
		util.Logger.Println("udp:recv data len error from " + udp_addr.String() + " : " + err.Error())
		return
	}

	dest_port := binary.BigEndian.Uint16(dec_data[1:3])
	dest_ip:=dec_data[3:dest_addr_len+1]
	origin_port := binary.BigEndian.Uint16(dec_data[dest_addr_len+1:dest_addr_len+3])
	real_data:=dec_data[dest_addr_len+3:]
	if dest_port==53{
		util.Logger.Println("connection log:maybe domain parse request. data_str:" + string(real_data))
	}

	//dest_addr := &net.UDPAddr{
	//	IP:   dec_data[3:dest_addr_len+1],
	//	Port: ,
	//	Zone: "",
	//}


	var dest_addr syscall.Sockaddr
	var source_addr syscall.Sockaddr


	if len(dest_ip)==4{
		addr:=[4]byte{}
		for i,v:=range dest_ip{
			addr[i]=v
		}
		dest_addr=&syscall.SockaddrInet4{
			Port: int(dest_port),
			Addr: addr,
		}
		source_addr=&syscall.SockaddrInet4{
			Port: int(origin_port),
			Addr: [4]byte{},
		}
	}else if  len(dest_ip)==16{
		addr:=[16]byte{}
		for i,v:=range dest_ip{
			addr[i]=v
		}
		dest_addr=&syscall.SockaddrInet6{
			Port: int(dest_port),
			Addr: addr,
		}
		source_addr=&syscall.SockaddrInet6{
			Port: int(origin_port),
			Addr: [16]byte{},
		}
	}else{
		util.Logger.Println("udp:illegal ip len ,unknow ip type from " + udp_addr.String() + " : " + err.Error())
		return
	}

	f, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		util.Logger.Println("udp create socket error:"+err.Error())
		return
	}
	if err := syscall.SetsockoptInt(f, syscall.SOL_SOCKET, go_client.SO_REUSEPORT, 1); err != nil {
		util.Logger.Println("udp set socket option error:"+err.Error())
		return
	}
	if err := syscall.Bind(f, source_addr); err != nil {
		util.Logger.Println("udp socket bind error:"+err.Error())
		return
	}

	if err:=syscall.Connect(f, dest_addr);err!=nil{
		util.Logger.Println("udp socket connect error:"+err.Error())
		return
	}

	_target,err:=net.FileConn(os.NewFile(uintptr(f),""))
	target:=_target.(*net.UDPConn)



	//
	//target, err := net.DialUDP("udp", &net.UDPAddr{
	//	IP:   nil,
	//	Port: int(origin_port),
	//	Zone: "",
	//}, dest_addr)




	if err != nil {
		util.Logger.Println("udp : can not open fd from "+udp_addr.String() )
		return
	}

	defer target.Close()

	if _, werr := target.Write(real_data); werr != nil {

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
