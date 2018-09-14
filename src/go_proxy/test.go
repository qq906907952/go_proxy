package main

import (
	"net"
	"syscall"
	"os"
	"fmt"
	"go_proxy/util"
)

func main() {
	fmt.Println(net.ResolveIPAddr("ip","ipip.net"))
	return
	go func() {

		f, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
		if err != nil {
			panic(err)
		}
		if err := syscall.SetsockoptInt(f, syscall.SOL_SOCKET, 15, 1); err != nil {
			panic(err)
		}
		if err := syscall.Bind(f, &syscall.SockaddrInet4{
			Port: 999,
			Addr: [4]byte{0,0,0,0},
		}); err != nil {
			panic(err)
		}



		if err:=syscall.Connect(f, &syscall.SockaddrInet4{
			Port: 53,
			Addr: [4]byte{114,114,114,114},
		});err!=nil{
			panic(err)
		}
		c, err := net.FileConn(os.NewFile(uintptr(f), "a"))
		if err != nil {
			panic(err)
		}
		dns := (&util.DNSStruct{})
		dns.Fill_question("baidu.com",util.A_record)
		c.Write(dns.Marshal_request())
		b:=make([]byte,10240)
		i,err:=c.Read(b)
		if err!=nil{
			fmt.Println(err)
		}
		fmt.Println("111")
		fmt.Println(string(b[:i]))
	}()


	f, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM,0)
	if err != nil {
		panic(err)
	}
	if err := syscall.SetsockoptInt(f, syscall.SOL_SOCKET, 15, 1); err != nil {
		panic(err)
	}
	if err := syscall.Bind(f, &syscall.SockaddrInet4{
		Port: 999,
		Addr: [4]byte{0,0,0,0},
	}); err != nil {
		panic(err)
	}




	if err:=syscall.Connect(f, &syscall.SockaddrInet4{
		Port: 53,
		Addr: [4]byte{223,5,5,5},
	});err!=nil{
		panic(err)
	}

	c, err := net.FileConn(os.NewFile(uintptr(f), "b"))
	if err != nil {
		panic(err)
	}

	dns := (&util.DNSStruct{})
	dns.Fill_question("youku.com",util.A_record)
	c.Write(dns.Marshal_request())
	b:=make([]byte,10240)
	i,err:=c.Read(b)
	if err!=nil{
		fmt.Println(err)
	}
	fmt.Println("222")
	fmt.Println(string(b[:i]))
}
