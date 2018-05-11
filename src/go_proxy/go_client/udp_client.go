package go_client
//
//import (
//	"net"
//	"log"
//	"syscall"
//
//	"bytes"
//	"go_proxy/util"
//	"encoding/binary"
//	"fmt"
//)
//
//const SO_REUSEPORT = 15
//
//func Start_UDPclien() {
//	defer util.Group.Done()
//	listen, err := net.ListenUDP("udp", &net.UDPAddr{
//		IP:   net.ParseIP(util.Config.Client.Local_addr),
//		Port: util.Config.Client.Local_port,
//		Zone: "",
//	})
//
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	defer listen.Close()
//
//	file, err := listen.File()
//	if err != nil {
//		log.Fatal(err)
//		return
//	}
//
//	syscall.SetsockoptInt(int(file.Fd()), syscall.SOL_IP, syscall.IP_RECVORIGDSTADDR, 1)
//	syscall.SetsockoptInt(int(file.Fd()), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
//	syscall.SetsockoptInt(int(file.Fd()), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
//
//	for {
//		data := make([]byte, util.Udp_recv_buff)
//		//store the additional data include the dest addr
//		oob := make([]byte, 1024)
//
//		i, oobi, _, addr, err := listen.ReadMsgUDP(data, oob)
//
//		if err != nil {
//			continue
//		}
//
//		msgs, err := syscall.ParseSocketControlMessage(oob[:oobi])
//		if err != nil {
//			continue
//		}
//
//		for _, msg := range msgs {
//			if msg.Header.Type == syscall.IP_RECVORIGDSTADDR {
//
//				go handle_udp_data(listen, addr, data[:i], msg.Data[2:8], crypt)
//				break
//			}
//		}
//
//	}
//
//}
//
//func handle_udp_data(local *net.UDPConn, udp_addr *net.UDPAddr, data, dest []byte, crypt util.Crypt_interface) {
//
//	defer util.Handle_panic()
//
//	dest_port := binary.BigEndian.Uint16(dest[:2])
//	origin_port := make([]byte, 2)
//	binary.BigEndian.PutUint16(origin_port, uint16(udp_addr.Port))
//
//	//send enc data
//	var enc_data []byte
//
//	if dest_port == 53 || (udp_addr.IP.IsLoopback() && int(dest_port) == util.Config.Client.Local_port) {
//
//		dns_port := make([]byte, 2)
//
//		binary.BigEndian.PutUint16(dns_port, uint16(util.Dns_address.Port))
//		dest_addr := bytes.Join([][]byte{dns_port, util.Dns_address.IP.To4()}, nil)
//		enc_data = crypt.Encrypt(bytes.Join([][]byte{{byte(len(dest_addr))}, dest_addr, origin_port, data}, nil))
//
//	} else {
//
//		enc_data = crypt.Encrypt(bytes.Join([][]byte{{byte(len(dest))}, dest, origin_port, data}, nil))
//	}
//
//	//connect udp to remote proxy server
//	con, err := net.Dial("udp", fmt.Sprintf("%s:%d", util.Config.Client.Server_addr, util.Config.Client.Server_port))
//
//	if err != nil {
//		util.Logger.Println("can not connect to server:" + err.Error())
//		return
//	}
//
//	remote := con.(*net.UDPConn)
//
//	defer remote.Close()
//
//	_, werr := remote.Write(enc_data)
//
//	if werr != nil {
//
//		//util.Logger.Println("udp write to proxy server error "+werr.Error())
//		return
//	}
//
//	//read data and dec
//	recv := make([]byte, util.Udp_recv_buff)
//
//	i, err := remote.Read(recv)
//
//	if err != nil {
//
//		return
//	}
//
//	if i > 0 {
//		dec_data, err := crypt.Decrypt(recv[:i])
//
//		if err != nil {
//			return
//		}
//
//		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
//		if err != nil {
//			return
//		}
//		defer syscall.Close(fd)
//		syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
//		syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, SO_REUSEPORT, 1)
//
//		if err := syscall.Bind(fd, &syscall.SockaddrInet4{
//			Port: int(dest_port),
//			Addr: [4]byte{dest[2], dest[3], dest[4], dest[5]},
//		}); err != nil {
//			return
//		}
//
//		src_ip := udp_addr.IP.To4()
//		if err := syscall.Connect(fd, &syscall.SockaddrInet4{
//			Port: udp_addr.Port,
//			Addr: [4]byte{src_ip[0], src_ip[1], src_ip[2], src_ip[3]},
//		}); err != nil {
//			return
//		}
//		syscall.Write(fd, dec_data)
//	}
//}
