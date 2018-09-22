package util

import (
	"log"
	"os"
	"runtime/debug"
	"fmt"
	"time"
)


var Log = log.Logger{}


func Print_log(log string,v... interface{}){

	file, err := os.OpenFile("go_proxy.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err!=nil{
		fmt.Println("can not open log file:"+err.Error())
		fmt.Println("==============================")
		return
	}
	Log.SetOutput(file)
	Log.Printf(time.Now().Format(time.RFC3339)+"	"+log,v...)
}


func Handle_panic() {
	err := recover()

	if err != nil {
		Log.Print("panic : ")
		Log.Println(err)

		debug.PrintStack()
		fmt.Println("==============================")


	}

}
