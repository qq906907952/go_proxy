package util

import (
	"log"
	"os"
	"time"
	"runtime/debug"
	"fmt"
)

var Logger log.Logger

func init() {
	_, err := os.Stat("log/")
	if err != nil {
		err := os.Mkdir("log", 0644)
		if err != nil {
			log.Fatal(err)
		}
	}

	file, err := os.OpenFile("log/go_proxy.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)

	if err != nil {
		log.Fatal(err)
	}
	Logger.SetOutput(file)
	Logger.SetPrefix(time.Now().String() + "	")
}



func Handle_panic() {
	err := recover()

	if err != nil {
		Logger.Print("panic : ")
		Logger.Println(err)

		debug.PrintStack()
		fmt.Println("==============================")


	}

}
