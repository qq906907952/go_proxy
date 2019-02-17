package local_proxy

import (
	"net"
	"go_proxy/util"
	"bytes"
	"encoding/binary"
	"strconv"
)

func handle_socks5_tcp(local *net.TCPConn, request []byte) {
	flag := request[3]

	switch flag {
	//is domain
	case 3:
		handle_domain(local)

		//is ipv4
	case 1:

		ip, err := util.Read_tcp_data(local, 4)

		if err != nil {
			return
		}

		port, err := util.Read_tcp_data(local, 2)

		if err != nil {
			return
		}
		handle_ip(local, ip, port)

		// is ipv6
	case 4:
		ip, err := util.Read_tcp_data(local, 16)
		if err != nil {
			return
		}

		port, err := util.Read_tcp_data(local, 2)

		if err != nil {
			return
		}
		handle_ip(local, ip, port)

	default:
		return
	}

}

func construct_sock5_reply() []byte {
	var atype byte
	atype = 1

	return bytes.Join([][]byte{[]byte{5, 0, 0, atype}, []byte{0, 0, 0, 0}, []byte{0, 0}}, nil)
}

func handle_domain(local *net.TCPConn) {

	var err error

	domain_len := make([]byte, 1)
	if _, err = local.Read(domain_len); err != nil {
		return
	}

	domain, err := util.Read_tcp_data(local, int(domain_len[0]))
	if err != nil {
		util.Print_log("read socks5 domain error:" + err.Error())
		return
	}

	port, err := util.Read_tcp_data(local, 2)
	if err != nil {
		util.Print_log("read socks5 port error:" + err.Error())
		return
	}
	dest_domain := string(domain)
	if util.Is_domain(dest_domain) {
		if util.Config.Connection_log {
			util.Print_log("connection log:%s connect to %s", local.RemoteAddr().String(), dest_domain+":"+strconv.Itoa(int(binary.BigEndian.Uint16(port))))
		}
		is_cn_domain, err := util.Is_china_domain(dest_domain)
		if err != nil {
			return
		}
		if is_cn_domain {

			ip, err := net.ResolveIPAddr("ip", dest_domain)

			if err != nil {
				util.Print_log("can not reslove domain:" + dest_domain + " " + err.Error())
				return
			}

			handle_connection(local, ip, int(binary.BigEndian.Uint16(port)), nil, construct_sock5_reply(), is_cn_domain)
		} else {

			dest_ip, err := util.Parse_not_cn_domain(string(domain), tcp_crypt, udp_crypt)

			if err != nil {
				util.Print_log("can not reslove domain:" + dest_domain + " " + err.Error())
				return
			}

			handle_connection(local, &net.IPAddr{
				IP:   dest_ip,
				Zone: "",
			}, int(binary.BigEndian.Uint16(port)), nil, construct_sock5_reply(), is_cn_domain)

		}
	} else {

		ip := net.ParseIP(dest_domain)

		if ip != nil {
			if ip.To4() != nil {
				handle_ip(local, ip.To4(), port)
			} else {
				handle_ip(local, ip.To16(), port)
			}

		} else {
			util.Print_log("socks5 recv a unknow addr:" + dest_domain)
		}

	}
}

func handle_ip(local *net.TCPConn, ip, port []byte) {
	dest_ip := &net.IPAddr{
		IP:   ip,
		Zone: "",
	}
	dest_port := int(binary.BigEndian.Uint16(port))
	if util.Config.Connection_log {
		util.Print_log("connection log:%s connect to %s", local.RemoteAddr().String(), dest_ip.String()+":"+strconv.Itoa(dest_port))
	}
	is_cn := false
	var err error
	if len(ip) == 4 {
		is_cn, err = util.Is_china_ipv4_addr(dest_ip.String())

		if err != nil {
			return
		}

	}

	handle_connection(local, dest_ip, dest_port, nil, construct_sock5_reply(), is_cn)

}

func handle_socks5_udp(local *net.TCPConn, request []byte) {

}
