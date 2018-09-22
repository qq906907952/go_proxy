package util

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"time"
)

var china_ipv4 = map[int]int{}

const (
	Udp_recv_buff = 65500
	Tcp_recv_buff = 65500
	SO_ORIGIN_DST = 80
	Tcp_conn      = 1
	Udp_conn      = 0
)

//get the tcp origin addrress after iptables nat redirectr
//func Get_tcp_origin_dest(con *net.TCPConn) (*syscall.IPv6Mreq, error) {
//	file, err := con.File()
//	if err != nil {
//		return nil, err
//
//	}
//
//	//sockopt const so_origin_dest = 80
//	addr, err := syscall.GetsockoptIPv6Mreq(int(file.Fd()), syscall.SOL_IP, SO_ORIGIN_DST)
//	if err != nil {
//		return nil, err
//	}
//
//	return addr, nil
//}

func Ipv4str2int(ip string) (int, error) {
	ipstr := strings.Split(ip, ".")
	if len(ipstr) != 4 {
		return 0, errors.New("ip illegal")
	}
	ip1, _ := strconv.Atoi(ipstr[0])
	ip2, _ := strconv.Atoi(ipstr[1])
	ip3, _ := strconv.Atoi(ipstr[2])
	ip4, _ := strconv.Atoi(ipstr[3])

	return ip1<<24 + ip2<<16 + ip3<<8 + ip4, nil

}

func Is_china_ipv4_addr(ip string) (bool, error) {


	dest_ipint, err := Ipv4str2int(ip)
	if err != nil {
		return false, err
	}
	for mask := 0; mask <= 32; mask++ {
		if v, ok := china_ipv4[dest_ipint&(int((math.Pow(2, float64(mask)))-1)<<uint(32-mask))]; ok {
			if v == mask {
				return true, nil
			}
		}
	}

	return false, nil


}

func Connect_to_server(crypt Crypt_interface, request_type, dest_port int, ip net.IP) (*net.TCPConn, error) {
	con, err := net.Dial("tcp", fmt.Sprintf("%s:%d", Config.Client.Server_addr, Config.Client.Server_port))

	if err != nil {

		return nil, err
	}
	remote := con.(*net.TCPConn)
	remote.SetKeepAlive(true)
	remote.SetKeepAlivePeriod(10*time.Second)
	timestamp_bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp_bytes, uint64(time.Now().Unix()))

	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(dest_port))
	dest_addr := bytes.Join([][]byte{port, ip}, nil)
	dest_addr_len := byte(len(dest_addr))

	if err := crypt.Write(remote, bytes.Join([][]byte{timestamp_bytes, {byte(request_type)}, {dest_addr_len,}, dest_addr,}, nil)); err != nil {
		return nil, err
	}

	return remote, nil
}

func Read_data_len(con *net.TCPConn) (int, error) {
	len_byte := make([]byte, 2)
	i, err := io.ReadAtLeast(con, len_byte, 2)

	if i != 2 {
		return 0, err
	}

	return int(binary.BigEndian.Uint16(len_byte)), nil
}

func Read_tcp_data(con *net.TCPConn, data_len int) ([]byte, error) {

	data := make([]byte, data_len)
	i, err := io.ReadAtLeast(con, data, data_len)
	if i == data_len {
		return data, err
	}

	return nil, err
}

func Read_at_least_byte(con *net.TCPConn, b []byte) ([]byte, []byte, error) {
	recv := []byte{}
	temp := make([]byte, Tcp_recv_buff)
	for {

		i, err := con.Read(temp)
		if i > 0 {
			recv = bytes.Join([][]byte{recv, temp[:i]}, nil)
			if ii := bytes.Index(recv, b); ii != -1 {
				return recv[:ii+len(b)], recv[ii+len(b):], nil
			}
			continue
		}

		if err != nil {
			return nil, nil, err
		}

	}
}

func Connection_loop(con1, con2 *net.TCPConn, crypt Crypt_interface) {
	//con1 read raw ,enc and write to con2
	//con2 read enc data ,dec and write to con1



	go func() {
		defer Handle_panic()
		defer con1.Close()
		defer con2.Close()

		for {
			data := make([]byte, Tcp_recv_buff)
			i, err := con1.Read(data)
			if i > 0 {

				if err := crypt.Write(con2, data[:i]); err != nil {
					return
				}
			}

			if err != nil {
				return
			}
		}

	}()

	for {
		data, err := crypt.Read(con2)
		if data != nil {
			if _, err := con1.Write(data); err != nil {
				return
			}
		}

		if err != nil {
			return
		}
	}

}

