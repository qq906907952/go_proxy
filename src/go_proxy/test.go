package main

import (
	"fmt"
	"go_proxy/util"
)

func main() {

	fmt.Println(util.Parse_not_cn_domain("dongtaiwang.com",
		util.Get_crypt("chacha20"," miku chang wa yichibann kawaii ")))

}
