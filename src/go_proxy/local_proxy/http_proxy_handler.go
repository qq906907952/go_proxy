package local_proxy

import (
	"go_proxy/util"
	"net"
	"strconv"
	"strings"
)

const https_establish_reply = "HTTP/1.1 200 Connection Established\r\n\r\n"

func Handle_HTTP(local *net.TCPConn, host string, dest_port int, data []byte) {

	url := strings.TrimSpace(host)

	//handle domain
	if util.Is_domain(url) {

		is_cn, err := util.Is_china_domain(url)

		if err != nil {
			util.Print_log("cn domain decision error:"+err.Error())
			return
		}

		if is_cn {
			ip, err := net.ResolveIPAddr("ip", url)
			if err != nil {
				util.Print_log("can not reslove domain " + url + " " + err.Error())
				return
			}
			handle_connection(local, ip, dest_port, data, nil, is_cn)

		} else {

			dest_ip, err := util.Parse_not_cn_domain(url, crypt)


			if err != nil {
				util.Print_log("can not reslove domain:" + url + " " + err.Error())
				return
			}

			handle_connection(local, &net.IPAddr{
				IP:   dest_ip,
				Zone: "",
			}, dest_port, data, nil, is_cn)

		}

	} else {
		ip := net.ParseIP(url)
		if ip.To4() == nil {
			handle_connection(local, &net.IPAddr{
				IP:   net.ParseIP(url),
				Zone: "",
			}, dest_port, data, nil, false)
		} else {
			is_cn, err := util.Is_china_ipv4_addr(url)

			if err != nil {
				return
			}

			handle_connection(local, &net.IPAddr{
				IP:   net.ParseIP(url),
				Zone: "",
			}, dest_port, data, nil, is_cn)
		}

	}

}

func Handle_HTTPS(local *net.TCPConn, host string) {

	host_spl := strings.Split(host, ":")

	var dest_port int

	if len(host_spl) == 2 {
		var err error
		dest_port, err = strconv.Atoi(host_spl[1])
		if err != nil {
			return
		}

	} else {
		return
	}

	url := strings.TrimSpace(host_spl[0])

	is_domain := util.Is_domain(url)

	if is_domain {

		is_cn, err := util.Is_china_domain(url)

		if err != nil {
			util.Print_log("cn domain decision error:"+err.Error())
			return
		}

		if is_cn {
			ip, err := net.ResolveIPAddr("ip", url)
			if err != nil {
				util.Print_log("can not reslove domain " + url + " " + err.Error())
				return
			}

			handle_connection(local, ip, dest_port, nil, []byte(https_establish_reply), is_cn)

		} else {

			dest_ip, err := util.Parse_not_cn_domain(url, crypt, )

			if err != nil {
				util.Print_log("can not reslove domain:" + url + " " + err.Error())
				return
			}

			handle_connection(local, &net.IPAddr{
				IP:   dest_ip,
				Zone: "",
			}, dest_port, nil, []byte(https_establish_reply), is_cn)

		}

	} else {
		ip := net.ParseIP(url)
		if ip.To4() == nil {
			handle_connection(local, &net.IPAddr{
				IP:   ip,
				Zone: "",
			}, dest_port, nil, []byte(https_establish_reply), false)

		} else {
			is_cn, err := util.Is_china_ipv4_addr(url)
			if err != nil {
				return
			}

			handle_connection(local, &net.IPAddr{
				IP:   net.ParseIP(url),
				Zone: "",
			}, dest_port, nil, []byte(https_establish_reply), is_cn)

		}
	}

}
