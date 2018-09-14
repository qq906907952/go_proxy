package util

import (
	"crypto/rand"
	"encoding/binary"
	"bytes"
	"strings"
	"net"
	"strconv"
	"errors"
	"fmt"
	"bufio"
	"os"
	"io"
	"sync"
)

var Dns_address *net.UDPAddr
var domain_map *saft_map
var ip_domain_map *saft_map

type saft_map struct {
	sync.RWMutex
	_map map[string]interface{}
}

func (this *saft_map) read(key string) (interface{}, bool) {
	this.RWMutex.RLock()
	value, ok := this._map[key]
	this.RWMutex.RUnlock()
	return value, ok
}

func (this *saft_map) write(key string, value interface{}) {
	this.RWMutex.Lock()
	this._map[key] = value
	this.RWMutex.Unlock()

}

func init() {
	domain_map = new(saft_map)
	domain_map._map = make(map[string]interface{})
	ip_domain_map = new(saft_map)
	ip_domain_map._map = make(map[string]interface{})
}

const (
	A_record    = 1
	AAAA_record = 28
)

type DNSStruct struct {
	//header
	ID      uint16
	Flag    uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16

	//question

	Qname  []byte
	Qtype  uint16
	Qclass uint16

	data []byte
}

//type DNSAnswer struct{
//	Name     []byte
//	Type     uint16
//	Class    uint16
//	TTL      uint32
//	RDLength uint16
//	RData    []byte
//}

func (this *DNSStruct) fill_header() {
	_rand_byte := make([]byte, 2)
	rand.Read(_rand_byte)
	this.ID = uint16(_rand_byte[0] + _rand_byte[1])
	this.Flag = 1 << 8
	this.QDCount = 1
	this.ANCount = 0
	this.NSCount = 0
	this.ARCount = 0

}

func (this *DNSStruct) Fill_question(domain string, qtype uint16) {

	this.fill_header()
	var qname []byte
	for _, i := range strings.Split(domain, ".") {

		length := make([]byte, 2)
		binary.BigEndian.PutUint16(length, uint16(len([]rune(i))))
		qname = bytes.Join([][]byte{qname, length[1:], []byte(i)}, nil)

	}
	qname = append(qname, 0)
	this.Qname = qname
	this.Qtype = qtype
	this.Qclass = 1

}

func (this *DNSStruct) Marshal_request() []byte {
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[:2], this.ID)
	binary.BigEndian.PutUint16(header[2:4], this.Flag)
	binary.BigEndian.PutUint16(header[4:6], this.QDCount)
	binary.BigEndian.PutUint16(header[6:8], this.ANCount)
	binary.BigEndian.PutUint16(header[8:10], this.NSCount)
	binary.BigEndian.PutUint16(header[10:12], this.ARCount)
	question := this.Qname
	qtype := make([]byte, 2)
	qclass := make([]byte, 2)
	binary.BigEndian.PutUint16(qtype, this.Qtype)
	binary.BigEndian.PutUint16(qclass, this.Qclass)
	return bytes.Join([][]byte{header, question, qtype, qclass}, nil)
}

func (this *DNSStruct) Get_rdata() ([]byte, error) {

	con, err := net.DialUDP("udp", nil, Dns_address)

	if err != nil {
		return nil, err
	}
	question := this.Marshal_request()
	con.Write(question)
	answer := make([]byte, 65535)
	i, err := con.Read(answer)

	if err != nil {
		return nil, err
	}
	if i < len(question)+12 {
		return nil, errors.New("illegal dns response")
	}

	answer = answer[len(question):i]

	return Get_record_from_answer(answer, this.Qtype)

}

func Get_record_from_answer(answer []byte, answer_type uint16) ([]byte, error) {
	if len(answer) < 12 {
		return nil, errors.New("can not found record")
	}
	if answer[0]&0xc0 == 0xc0 {
		_type := binary.BigEndian.Uint16(answer[2:4])
		rdate_len := binary.BigEndian.Uint16(answer[10:12])

		answer = answer[12:]
		if len(answer) < int(rdate_len) {
			return nil, errors.New("rdate len illegal")
		} else {
			if _type == answer_type {
				return answer[:rdate_len], nil
			}
			return Get_record_from_answer(answer[rdate_len:], answer_type)
		}

	} else {
		for i, v := range answer {
			if v == 0 {
				if len(answer)-i < 12 {
					return nil, errors.New("rdate len illegal")
				} else {
					answer = answer[i:]
					if answer[0]&0xc0 == 0xc0 {
						_type := binary.BigEndian.Uint16(answer[2:4])
						rdate_len := binary.BigEndian.Uint16(answer[10:12])
						answer = answer[12:]
						if len(answer) < int(rdate_len) {
							return nil, errors.New("rdate len illegal")
						}
						if _type == answer_type {
							return answer[:rdate_len], nil
						}
						return Get_record_from_answer(answer[rdate_len:], answer_type)

					} else {
						_type := binary.BigEndian.Uint16(answer[:2])

						rdate_len := binary.BigEndian.Uint16(answer[8:10])
						answer = answer[10:]

						if len(answer) < int(rdate_len) {
							return nil, errors.New("rdate len illegal")
						} else {
							if _type == answer_type {
								return answer[:rdate_len], nil
							}
							return Get_record_from_answer(answer[rdate_len:], answer_type)
						}
					}
				}
			}
		}
		return nil, errors.New("can not found record")
	}

}

func Is_domain(url string) bool {
	_sufix := strings.Split(url, ".")

	if _, serr := strconv.Atoi(_sufix[len(_sufix)-1]); serr != nil {
		return true
	} else {
		return false
	}
}

func Parse_not_cn_domain(domain string, crypt Crypt_interface) ([]byte, error) {

	if ip, ok := ip_domain_map.read(domain); ok {
		return ip.([]byte), nil
	}

	var ip []byte
	defer func() {
		if len(ip) != 0 {
			go func() {
				ip_domain_map.write(domain, ip)
			}()
		}
	}()
	switch Config.Client.Dns_req_proto {
	case "tcp":
		con, err := Connect_to_server(crypt, Udp_conn, Dns_address.Port, Dns_address.IP)
		if err != nil {
			return nil, err
		}
		defer con.Close()

		dns := &DNSStruct{}

		if Config.Client.Ipv6 {
			dns.Fill_question(domain, AAAA_record)
			request := dns.Marshal_request()
			if err := crypt.Write(con, request); err != nil {
				return nil, err
			}
			answer, err := crypt.Read(con)

			if len(answer) > len(request) {

				ip, err = Get_record_from_answer(answer[len(request):], AAAA_record)
				if err == nil {
					return ip, nil
				}
			}

		}

		dns.Fill_question(domain, A_record)
		request := dns.Marshal_request()
		if err := crypt.Write(con, request); err != nil {
			return nil, err
		}
		answer, err := crypt.Read(con)
		if len(answer) > len(request) {

			ip, err = Get_record_from_answer(answer[len(request):], A_record)
			if err == nil {
				return ip, nil
			}
		}
		return nil, errors.New("no recored found")

	case "udp":
		con, err := net.Dial("udp", fmt.Sprintf("%s:%d", Config.Client.Server_addr, Config.Client.Server_port))
		if err != nil {
			return nil, err
		}
		defer con.Close()

		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, uint16(Dns_address.Port))

		//dns_addr := Dns_address.IP.To4()
		//if dns_addr == nil {
		//	dns_addr = Dns_address.IP.To16()
		//}

		dest_addr := bytes.Join([][]byte{port, Dns_address.IP}, nil)
		dns := &DNSStruct{}

		var forward_dns_request = func(qtype uint16) ([]byte, error) {
			dns.Fill_question(domain, qtype)
			request := dns.Marshal_request()
			origin_port := make([]byte, 2)
			rand.Read(origin_port)
			con.Write(crypt.Encrypt(bytes.Join([][]byte{{byte(len(dest_addr))}, dest_addr, origin_port, request}, nil)))
			data := make([]byte, Udp_recv_buff)
			i, err := con.Read(data)
			if err != nil {
				return nil, err
			}
			answer, err := crypt.Decrypt(data[:i])
			if err != nil {
				return nil, err
			}
			if len(answer) < len(request)+12 {
				return nil, errors.New("len is illegal")
			}

			return Get_record_from_answer(answer[len(request):], qtype)

		}

		if Config.Client.Ipv6 {
			ip, err = forward_dns_request(AAAA_record)
			if err != nil {
				goto ipv4
			}
			return ip, nil

		}
	ipv4:
		ip, err = forward_dns_request(A_record)
		return ip, err
	default:
		return nil, errors.New("unsport proto")
	}

}

func Is_china_domain(domain string) (bool, error) {

	_domain := strings.Split(domain, ".")
	if len(_domain) < 2 {
		return false, errors.New("domain name illegal")
	}

	if is_cn, ok := domain_map.read(strings.Join(_domain[len(_domain)-2:], ".")); ok {
		return is_cn.(bool), nil
	}

	if _domain[len(_domain)-1] == "cn" {
		return true, nil
	}

	china_domain, err := os.Open("dnsmasq-china-list")
	if err != nil {
		return false, nil
	}
	defer china_domain.Close()

	reader := bufio.NewReader(china_domain)

	for {
		line, _, err := reader.ReadLine()
		if err != nil {
			if err == io.EOF {

				go func() {
					domain_map.write(strings.Join(_domain[len(_domain)-2:], "."), false)
				}()

				return false, nil

			} else {
				return false, err
			}
		}
		if len(line) == 0 {
			continue
		}
		if line_spl := strings.Split(string(line), "/"); len(line_spl) < 2 {

			continue

		} else {

			//if reg2.MatchString(domain) || reg.MatchString(domain) {
			if strings.Join(_domain[len(_domain)-2:], ".") == line_spl[1] {
				go func() {
					domain_map.write(strings.Join(_domain[len(_domain)-2:], "."), true)

				}()
				return true, nil
			}
		}

	}

}
