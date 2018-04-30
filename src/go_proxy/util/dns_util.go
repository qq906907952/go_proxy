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
)

var Dns_address *net.UDPAddr

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

	switch Config.Client.Dns_req_proto {
	case "tcp":
		con, err := Connect_to_server(crypt, Udp_conn, Dns_address.Port, Dns_address.IP)
		if err != nil {
			return nil, err
		}
		defer con.Close()

		dns := &DNSStruct{}
		var ip_bytes []byte
		if Config.Client.Ipv6 {
			dns.Fill_question(domain, AAAA_record)
			request := dns.Marshal_request()
			if err := crypt.Write(con, request); err != nil {
				return nil, err
			}
			answer, err := crypt.Read(con)

			if len(answer) > len(request) {

				ip_bytes, err = Get_record_from_answer(answer[len(request):], AAAA_record)
				if err == nil {
					return ip_bytes, nil
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

			ip_bytes, err = Get_record_from_answer(answer[len(request):], A_record)
			if err == nil {
				return ip_bytes, nil
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

		dns_addr :=Dns_address.IP.To4()
		if dns_addr==nil{
			dns_addr=Dns_address.IP.To16()
		}

		dest_addr := bytes.Join([][]byte{port, dns_addr}, nil)
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
			ip, err := forward_dns_request(AAAA_record)
			if err != nil {
				goto ipv4
			}
			return ip, nil

		}
	ipv4:
		return forward_dns_request(A_record)
	default:
		return nil, errors.New("unsport proto")
	}

}
