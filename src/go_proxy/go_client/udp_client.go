package go_client

import (
	"net"
	"log"
	"syscall"

	"bytes"
	"go_proxy/util"
	"encoding/binary"
	"fmt"
	"time"
)

const SO_REUSEPORT = 15

func Start_UDPclien() {
	defer util.Group.Done()
	listen, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP(util.Config.Client.Local_addr),
		Port: util.Config.Client.Local_port,
		Zone: "",
	})

	if err != nil {
		log.Fatal(err)
	}

	defer listen.Close()

	file, err := listen.File()
	if err != nil {
		log.Fatal(err)
		return
	}

	syscall.SetsockoptInt(int(file.Fd()), syscall.SOL_IP, syscall.IP_RECVORIGDSTADDR, 1)
	syscall.SetsockoptInt(int(file.Fd()), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
	syscall.SetsockoptInt(int(file.Fd()), syscall.SOL_SOCKET, SO_REUSEPORT, 1)

	for {
		data := make([]byte, util.Udp_recv_buff)
		//store the additional data include the dest addr
		oob := make([]byte, 1024)

		i, oobi, _, addr, err := listen.ReadMsgUDP(data, oob)

		go func(data, oob []byte, n, oobn int, addr *net.UDPAddr, err error) {
			if err != nil {
				util.Logger.Println("udp read err :" + err.Error())
			}
			msgs, err := syscall.ParseSocketControlMessage(oob[:oobi])
			if err != nil {
				util.Logger.Println("can not read udp original dest :" + err.Error())

			}

			for _, msg := range msgs {
				if msg.Header.Type == syscall.IP_RECVORIGDSTADDR {

					handle_udp_data(listen, addr, data[:i], msg.Data[2:8], crypt)
					return
				}
			}
		}(data, oob, i, oobi, addr, err)

	}

}

func handle_udp_data(local *net.UDPConn, udp_addr *net.UDPAddr, data, dest []byte, crypt util.Crypt_interface) {

	if udp_addr.IP.To4() == nil {
		util.Logger.Println("iptables transparent not support ipv6")
		return
	}

	defer util.Handle_panic()

	dest_port := binary.BigEndian.Uint16(dest[:2])

	origin_port := make([]byte, 2)
	binary.BigEndian.PutUint16(origin_port, uint16(udp_addr.Port))
	origin_addr := bytes.Join([][]byte{origin_port, udp_addr.IP}, nil)

	//send enc data
	var enc_data []byte

	if dest_port == 53 || (udp_addr.IP.IsLoopback() && int(dest_port) == util.Config.Client.Local_port) {

		dns_port := make([]byte, 2)

		binary.BigEndian.PutUint16(dns_port, uint16(util.Dns_address.Port))
		dest_addr := bytes.Join([][]byte{dns_port, util.Dns_address.IP}, nil)

		enc_data = crypt.Encrypt(bytes.Join([][]byte{{byte(len(dest_addr))}, dest_addr,
			{byte(len(origin_addr))}, origin_addr,
			data}, nil))

		if util.Config.Connection_log {
			go func(){
				domain:=util.Get_domain_name_from_request(data)
				if domain!=""{
					util.Logger.Printf("connection log:%s query domain name %s" + domain)
				}
			}()
		}

	} else {

		enc_data = crypt.Encrypt(bytes.Join([][]byte{{byte(len(dest))}, dest, {byte(len(origin_addr))}, origin_addr, data}, nil))
	}

	//connect udp to remote proxy server
	con, err := net.Dial("udp", fmt.Sprintf("%s:%d", util.Config.Client.Server_addr, util.Config.Client.Server_port))

	if err != nil {
		util.Logger.Println("can not connect to remote:" + err.Error())
		return
	}

	remote := con.(*net.UDPConn)

	defer remote.Close()

	_, werr := remote.Write(enc_data)

	if werr != nil {

		util.Logger.Println("udp write to remote error " + werr.Error())
		return
	}

	//read data and dec
	recv := make([]byte, util.Udp_recv_buff)

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return
	}
	sour_ip := [4]byte{}
	for i, v := range udp_addr.IP.To4() {
		sour_ip[i] = v
	}

	defer syscall.Close(fd)
	syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, SO_REUSEPORT, 1)

	if err := syscall.Bind(fd, &syscall.SockaddrInet4{
		Port: int(dest_port),
		Addr: [4]byte{dest[2], dest[3], dest[4], dest[5]},
	}); err != nil {
		return
	}

	if err := syscall.Connect(fd, &syscall.SockaddrInet4{
		Port: udp_addr.Port,
		Addr: sour_ip,
	}); err != nil {
		util.Logger.Println("create udp socket error:" + err.Error())
		return
	}

	for {
		if err := remote.SetReadDeadline(time.Now().Add(time.Duration(util.Config.Udp_timeout) * time.Second)); err != nil {
			util.Logger.Println("set udp read deadline error" + err.Error())
			return
		}
		i, err := remote.Read(recv)
		if i > 0 {
			dec_data, err := crypt.Decrypt(recv[:i])

			if err != nil {
				return
			}
			syscall.Write(fd, dec_data)
		}

		if err != nil {
			return
		}
	}
}
