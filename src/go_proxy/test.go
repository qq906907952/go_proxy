package main

import (
	"net"
	"fmt"
)

func main() {
	l,err:=net.DialTCP("tcp",nil,&net.TCPAddr{
		IP:  net.ParseIP("172.217.31.238"),
		Port: 80,
		Zone: "",
	})
	if err!=nil{
		panic(err)
	}
	fmt.Println(l.Close())
	fmt.Println(l.Close())
}

