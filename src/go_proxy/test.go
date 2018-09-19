package main

import (
	"go_proxy/util"
	"fmt"
)

func main() {
	dns:=util.DNSStruct{

	}
	dns.Fill_question("baidu.com",util.A_record)
	fmt.Println(util.Get_domain_name_from_request(dns.Marshal_request()))
}
