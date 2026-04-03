package main

// #include <stdlib.h>
import "C"

import (
	"context"
	"sync"
	"unsafe"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	_ "github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

var (
	instance       *box.Box
	instanceCtx    context.Context
	instanceCancel context.CancelFunc
	instanceMutex  sync.Mutex
)

//export libbox_run
func libbox_run(configContent *C.char) *C.char {
	instanceMutex.Lock()
	defer instanceMutex.Unlock()

	if instance != nil {
		return C.CString("service already running")
	}

	configStr := C.GoString(configContent)
	var options option.Options
	err := json.Unmarshal([]byte(configStr), &options)
	if err != nil {
		return C.CString(err.Error())
	}

	baseCtx := include.Context(context.Background())
	ctx, cancel := context.WithCancel(baseCtx)
	instance, err = box.New(box.Options{
		Context: ctx,
		Options: options,
	})
	if err != nil {
		cancel()
		return C.CString(err.Error())
	}

	err = instance.Start()
	if err != nil {
		instance.Close()
		instance = nil
		cancel()
		return C.CString(err.Error())
	}

	instanceCtx = ctx
	instanceCancel = cancel
	return nil
}

//export libbox_stop
func libbox_stop() *C.char {
	instanceMutex.Lock()
	defer instanceMutex.Unlock()

	if instance == nil {
		return C.CString("service not running")
	}

	instanceCancel()
	err := instance.Close()
	instance = nil
	instanceCtx = nil
	instanceCancel = nil

	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export libbox_free_string
func libbox_free_string(str *C.char) {
	C.free(unsafe.Pointer(str))
}

func main() {}
