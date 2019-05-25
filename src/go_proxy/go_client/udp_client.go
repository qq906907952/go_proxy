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

	"errors"
)

const SO_REUSEPORT = 15

var (
	remote_connection *net.UDPConn
	remote_udp_addr   = &net.UDPAddr{
		IP:   net.ParseIP(util.Config.Client.Server_addr),
		Port: util.Config.Client.Server_port,
	}
	data_chan = make(chan []byte, 200)
)

func Start_UDPclien() {
	defer util.Group.Done()

	udp_crypt := util.Get_crypt(util.Config.Client.Enc_method, util.Config.Client.Password)
	tcp_crypt:=util.Get_crypt(util.Config.Client.Enc_method, util.Config.Client.Password)
	if util.Config.Client.Tls.Turn && !util.Config.Client.Tls.Tcp_encrypt {
		tcp_crypt = util.Get_none_crypt()
	}
	listen, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP(util.Config.Client.Local_addr),
		Port: util.Config.Client.Local_port,
		Zone: "",
	})

	if err != nil {
		panic(err)
	}

	remote_connection, err = net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		panic(err)
	}

	defer listen.Close()

	file, err := listen.File()
	if err != nil {
		log.Fatal(err)
		return
	}

	if err:=syscall.SetsockoptInt(int(file.Fd()), syscall.SOL_IP, syscall.IP_RECVORIGDSTADDR, 1);err!=nil{
		panic(err)
	}
	if err:=syscall.SetsockoptInt(int(file.Fd()), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1);err!=nil{
		panic(err)
	}
	if err:=syscall.SetsockoptInt(int(file.Fd()), syscall.SOL_SOCKET, SO_REUSEPORT, 1);err!=nil{
		panic(err)
	}

	_l := fmt.Sprintf("udp client listen on %s:%d,remote server %s:%d \r\ncrypt method:%s",
		util.Config.Client.Local_addr,
		util.Config.Client.Local_port,
		util.Config.Client.Server_addr,
		util.Config.Client.Server_port,
		udp_crypt.String())
	util.Print_log(_l)
	fmt.Println(_l)

	go udp_loop(udp_crypt)

	for {
		data := make([]byte, util.Udp_recv_buff)
		//store the additional data include the dest addr
		oob := make([]byte, 1024)

		i, oobi, _, addr, err := listen.ReadMsgUDP(data, oob)

		go func(data, oob []byte, n, oobn int, addr *net.UDPAddr, err error) {
			if err != nil {
				util.Print_log("udp read err :" + err.Error())
			}
			msgs, err := syscall.ParseSocketControlMessage(oob[:oobi])
			if err != nil {
				util.Print_log("can not read udp original dest :" + err.Error())

			}

			for _, msg := range msgs {
				if msg.Header.Type == syscall.IP_RECVORIGDSTADDR {
					handle_udp_data(listen, addr, data[:i], msg.Data[2:8], udp_crypt,tcp_crypt)
					return
				}
			}
		}(data, oob, i, oobi, addr, err)

	}

}

func handle_udp_data(local *net.UDPConn, udp_addr *net.UDPAddr, data, dest []byte, udp_crypt,tcp_crypt util.Crypt_interface) {

	if udp_addr.IP.To4() == nil {
		util.Print_log("iptables transparent not support ipv6")
		return
	}

	defer util.Handle_panic()

	dest_port := binary.BigEndian.Uint16(dest[:2])
	origin_port := make([]byte, 2)
	binary.BigEndian.PutUint16(origin_port, uint16(udp_addr.Port))
	origin_addr := bytes.Join([][]byte{origin_port, udp_addr.IP.To4()}, nil)

	// handle dns request
	if dest_port == 53 || (udp_addr.IP.IsLoopback() && int(dest_port) == util.Config.Client.Local_port) {

		dns_port := make([]byte, 2)

		binary.BigEndian.PutUint16(dns_port, uint16(util.Dns_address.Port))
		dest_addr := bytes.Join([][]byte{dns_port, util.Dns_address.IP}, nil)

		if util.Config.Connection_log {
			go func() {
				domain := util.Get_domain_name_from_request(data)
				if domain != "" {
					util.Print_log("connection log:%s query domain name %s", udp_addr.String(), domain)
				}
			}()
		}
		switch util.Config.Client.Dns_req_proto{
		case "tcp":

			con, raw, err := util.Connect_to_server(tcp_crypt, util.Udp_conn, util.Dns_address.Port,util.Dns_address.IP)
			if err != nil {
				util.Print_log("can not connect to remote:" + err.Error())
			}

			defer util.Close_tcp(raw)

			if err := tcp_crypt.Write(con, data); err != nil {
				util.Print_log("can not write to remote:" + err.Error())
				return
			}

			if err := con.SetReadDeadline(time.Now().Add(time.Duration(util.Config.Udp_timeout) * time.Second)); err != nil {
				util.Print_log("set tcp read deadline error" + err.Error())
				return
			}
			real_data, err := tcp_crypt.Read(con)
			if err!=nil{
				util.Print_log("read from remote fail:" + err.Error())
				return
			}

			sour_ip := [4]byte{}
			for i, v := range udp_addr.IP.To4() {
				sour_ip[i] = v
			}

			if err:=write_to_local(int(dest_port),udp_addr.Port,
				[4]byte{dest[2], dest[3], dest[4], dest[5]},
				sour_ip,
				real_data);err!=nil{
				util.Print_log(err.Error())
				return
			}

		case "udp":
			enc_data := udp_crypt.Encrypt(bytes.Join([][]byte{{byte(len(dest_addr))}, dest_addr,
				{byte(len(origin_addr))}, origin_addr,
				data}, nil))
			con, err := net.Dial("udp", fmt.Sprintf("%s:%d", util.Config.Client.Server_addr, util.Config.Client.Server_port))
			if err != nil {
				util.Print_log("can not connect to remote:" + err.Error())
				return
			}
			remote := con.(*net.UDPConn)
			defer remote.Close()

			remote.Write(enc_data)

			for {

				if err := remote.SetReadDeadline(time.Now().Add(time.Duration(util.Config.Udp_timeout) * time.Second)); err != nil {
					util.Print_log("set udp read deadline error" + err.Error())
					return
				}
				recv := make([]byte, util.Udp_recv_buff)
				i, err := remote.Read(recv)

				if i > 0 {
					dec_data, err := udp_crypt.Decrypt(recv[:i])
					if err != nil {
						util.Print_log("decrypt err:" + err.Error())
						continue
					}
					_, _, _, _, real_data, err := util.Parse_udp_recv(dec_data)

					if err != nil {
						util.Print_log("parse udp recv fail :" + err.Error())
						continue
					}
					sour_ip := [4]byte{}
					for i, v := range udp_addr.IP.To4() {
						sour_ip[i] = v
					}

					if err:=write_to_local(int(dest_port),udp_addr.Port,
						[4]byte{dest[2], dest[3], dest[4], dest[5]},
						sour_ip,
						real_data);err!=nil{
							util.Print_log(err.Error())
							continue
					}

				}
				if err != nil {
					util.Print_log("remote udp connection error : " + err.Error())
					return
				}
			}
		default:
			return
		}


	} else {
		enc_data := udp_crypt.Encrypt(bytes.Join([][]byte{{byte(len(dest))}, dest, {byte(len(origin_addr))}, origin_addr, data}, nil))
		data_chan <- enc_data
	}

}

func udp_loop(crypt util.Crypt_interface) {

	go func(crypt util.Crypt_interface) {
		for {
			recv := make([]byte, util.Udp_recv_buff)

			i, err := remote_connection.Read(recv)

			if i > 0 {

				dec_data, err := crypt.Decrypt(recv[:i])
				if err != nil {
					util.Print_log("decrypt err:" + err.Error())
					continue
				}

				dest_ip, sour_ip, dest_port, source_port, real_data, err := util.Parse_udp_recv(dec_data)
				if err != nil {
					util.Print_log("parse udp recv fail :" + err.Error())
					continue
				}


				if err:=write_to_local(dest_port,source_port,dest_ip,sour_ip,real_data);err!=nil{
					util.Print_log(err.Error())
					continue
				}

			}

			if err != nil {
				util.Print_log("remote udp connection error : " + err.Error())
			}
		}
	}(crypt)

	for {
		select {
		case recv := <-data_chan:
			remote_connection.WriteTo(recv, remote_udp_addr)
		}
	}
}



func write_to_local(bind_port,to_port int,bind_ip,to_ip [4]byte,data []byte)error{
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return errors.New("create udp socket error:" + err.Error())
	}
	defer syscall.Close(fd)

	syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, SO_REUSEPORT, 1)

	if err := syscall.Bind(fd, &syscall.SockaddrInet4{
		Port: bind_port,
		Addr: bind_ip,
	}); err != nil {
		return errors.New("bind udp addr error:" + err.Error())
	}

	if err := syscall.Connect(fd, &syscall.SockaddrInet4{
		Port: to_port,
		Addr: to_ip,
	}); err != nil {
		return errors.New("udp addr connect error:" + err.Error())
	}
	_,err=syscall.Write(fd, data)
	return err

}