package main

import (
	"net"
	"syscall"
	"fmt"
)

func main() {
	con,err:=net.Dial("tcp","baidu.com:80")
	if err!=nil{
		panic(err)
	}
	c:=con.(*net.TCPConn)
	f,_:=c.File()
	fd:=int(f.Fd())
	syscall.SetNonblock(fd,true)
	b:=make([]byte,10240)
	i,err:=syscall.Pread(fd,b,0)
	if err!=nil{
		panic(err)
	}
	fmt.Println(string(b[:i]))

}
