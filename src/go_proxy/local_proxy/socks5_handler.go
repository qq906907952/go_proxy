package local_proxy

import (
	"net"
	"go_proxy/util"
	"bytes"
	"encoding/binary"
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

func write_sock5_reply(con *net.TCPConn, atype byte) error {
	local_port := make([]byte, 2)
	binary.BigEndian.PutUint16(local_port, uint16(util.Config.Client.Local_port))
	local_ip := net.ParseIP(util.Config.Client.Local_addr).To4()
	if local_ip == nil {
		local_ip = net.ParseIP(util.Config.Client.Local_addr).To16()
	}

	_, err := con.Write(bytes.Join([][]byte{[]byte{5, 0, 0, atype}, local_ip, local_port}, nil))
	return err
}

func handle_domain(local *net.TCPConn) {

	var err error

	domain_len := make([]byte, 1)
	if _, err = local.Read(domain_len); err != nil {
		return
	}

	domain, err := util.Read_tcp_data(local, int(domain_len[0]))
	port, err := util.Read_tcp_data(local, 2)
	if err != nil {

		return
	}
	dest_domain := string(domain)

	if util.Is_domain(dest_domain) {

		is_cn_domain, err := util.Is_china_domain(dest_domain)
		if err != nil {
			return
		}

		if is_cn_domain {

			ip, err := net.ResolveIPAddr("ip", dest_domain)

			if err != nil {
				util.Logger.Println("can not reslove domain:" + dest_domain + " " + err.Error())
				return
			}
			if err := write_sock5_reply(local, 1); err != nil {
				return
			}

			handle_connection(local, ip, int(binary.BigEndian.Uint16(port)), nil, nil, is_cn_domain)
		} else {

			dest_ip, err := util.Parse_not_cn_domain(string(domain), crypt)

			if err != nil {
				util.Logger.Println("can not reslove domain:" + dest_domain + " " + err.Error())
				return
			}

			if err := write_sock5_reply(local, 1); err != nil {
				return
			}

			handle_connection(local, &net.IPAddr{
				IP:   dest_ip,
				Zone: "",
			}, int(binary.BigEndian.Uint16(port)), nil, nil, is_cn_domain)

		}
	} else {
		return
	}
}

func handle_ip(local *net.TCPConn, ip, port []byte) {
	is_cn := false
	var err error
	if len(ip) == 4 {
		is_cn, err = util.Is_china_ipv4_addr(net.IP{ip[0], ip[1], ip[2], ip[3]}.String())
		if err != nil {

			return
		}

	}

	if err := write_sock5_reply(local, 1); err != nil {
		return
	}
	handle_connection(local, &net.IPAddr{
		IP:   ip,
		Zone: "",
	}, int(binary.BigEndian.Uint16(port)), nil, nil, is_cn)

}

func handle_socks5_udp(local *net.TCPConn, request []byte) {

}
