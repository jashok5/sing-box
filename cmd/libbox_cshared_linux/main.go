package main

// #include <stdint.h>
// #include <stdlib.h>
//
// typedef void (*libbox_log_callback)(void* user_data, int level, const char* message);
//
// static inline void libbox_invoke_log_callback(libbox_log_callback callback, void* user_data, int level, const char* message) {
//   callback(user_data, level, message);
// }
import "C"

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"unsafe"

	box "github.com/sagernet/sing-box"
	CBox "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	_ "github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service/filemanager"
)

var (
	instance       *box.Box
	instanceCtx    context.Context
	instanceCancel context.CancelFunc
	instanceMutex  sync.Mutex

	basePathMutex sync.RWMutex
	basePath      string
	workingPath   string
	tempPath      string

	logCallbackMutex    sync.RWMutex
	logCallback         C.libbox_log_callback
	logCallbackUserData unsafe.Pointer
)

type platformLogWriter struct{}

func (w *platformLogWriter) WriteMessage(level log.Level, message string) {
	logCallbackMutex.RLock()
	callback := logCallback
	userData := logCallbackUserData
	logCallbackMutex.RUnlock()
	if callback == nil {
		return
	}
	cMessage := C.CString(message)
	defer C.free(unsafe.Pointer(cMessage))
	C.libbox_invoke_log_callback(callback, userData, C.int(level), cMessage)
}

func baseContext() context.Context {
	ctx := include.Context(context.Background())

	basePathMutex.RLock()
	localBasePath := basePath
	localWorkingPath := workingPath
	localTempPath := tempPath
	basePathMutex.RUnlock()

	if localBasePath == "" || localWorkingPath == "" || localTempPath == "" {
		return ctx
	}

	_ = os.MkdirAll(localBasePath, 0o755)
	_ = os.MkdirAll(localWorkingPath, 0o755)
	_ = os.MkdirAll(localTempPath, 0o755)

	return filemanager.WithDefault(ctx, localWorkingPath, localTempPath, os.Getuid(), os.Getgid())
}

func parseConfig(ctx context.Context, configStr string) (option.Options, error) {
	return json.UnmarshalExtendedContext[option.Options](ctx, []byte(configStr))
}

func buildBox(configStr string) (*box.Box, context.Context, context.CancelFunc, error) {
	ctx, cancel := context.WithCancel(baseContext())

	options, err := parseConfig(ctx, configStr)
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}

	var platformWriter log.PlatformWriter
	logCallbackMutex.RLock()
	hasLogCallback := logCallback != nil
	logCallbackMutex.RUnlock()
	if hasLogCallback {
		platformWriter = (*platformLogWriter)(nil)
	}

	service, err := box.New(box.Options{
		Context:           ctx,
		Options:           options,
		PlatformLogWriter: platformWriter,
	})
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}

	return service, ctx, cancel, nil
}

func closeRunningInstanceLocked() error {
	if instance == nil {
		return nil
	}

	instanceCancel()
	err := instance.Close()
	instance = nil
	instanceCtx = nil
	instanceCancel = nil
	return err
}

func startNewInstanceLocked(configStr string) error {
	service, ctx, cancel, err := buildBox(configStr)
	if err != nil {
		return err
	}

	err = service.Start()
	if err != nil {
		service.Close()
		cancel()
		return err
	}

	instance = service
	instanceCtx = ctx
	instanceCancel = cancel
	return nil
}

//export libbox_run
func libbox_run(configContent *C.char) (ret *C.char) {
	defer func() {
		if recovered := recover(); recovered != nil {
			ret = C.CString(fmt.Sprintf("panic in libbox_run: %v\n%s", recovered, string(debug.Stack())))
		}
	}()

	instanceMutex.Lock()
	defer instanceMutex.Unlock()

	if instance != nil {
		return C.CString("service already running")
	}

	err := startNewInstanceLocked(C.GoString(configContent))
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export libbox_run_from_path
func libbox_run_from_path(configPath *C.char) *C.char {
	configBytes, err := os.ReadFile(C.GoString(configPath))
	if err != nil {
		return C.CString(err.Error())
	}
	configContent := C.CString(string(configBytes))
	defer C.free(unsafe.Pointer(configContent))
	return libbox_run(configContent)
}

//export libbox_stop
func libbox_stop() (ret *C.char) {
	defer func() {
		if recovered := recover(); recovered != nil {
			ret = C.CString(fmt.Sprintf("panic in libbox_stop: %v\n%s", recovered, string(debug.Stack())))
		}
	}()

	instanceMutex.Lock()
	defer instanceMutex.Unlock()

	if instance == nil {
		return C.CString("service not running")
	}

	err := closeRunningInstanceLocked()
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export libbox_reload
func libbox_reload(configContent *C.char) (ret *C.char) {
	defer func() {
		if recovered := recover(); recovered != nil {
			ret = C.CString(fmt.Sprintf("panic in libbox_reload: %v\n%s", recovered, string(debug.Stack())))
		}
	}()

	instanceMutex.Lock()
	defer instanceMutex.Unlock()

	if instance == nil {
		return C.CString("service not running")
	}

	configStr := C.GoString(configContent)
	closeErr := closeRunningInstanceLocked()
	if closeErr != nil {
		return C.CString(closeErr.Error())
	}

	err := startNewInstanceLocked(configStr)
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export libbox_start_or_reload
func libbox_start_or_reload(configContent *C.char) (ret *C.char) {
	defer func() {
		if recovered := recover(); recovered != nil {
			ret = C.CString(fmt.Sprintf("panic in libbox_start_or_reload: %v\n%s", recovered, string(debug.Stack())))
		}
	}()

	instanceMutex.Lock()
	defer instanceMutex.Unlock()

	configStr := C.GoString(configContent)
	if instance != nil {
		if err := closeRunningInstanceLocked(); err != nil {
			return C.CString(err.Error())
		}
	}

	err := startNewInstanceLocked(configStr)
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export libbox_is_running
func libbox_is_running() C.int {
	instanceMutex.Lock()
	defer instanceMutex.Unlock()
	if instance == nil {
		return 0
	}
	return 1
}

//export libbox_check_config
func libbox_check_config(configContent *C.char) (ret *C.char) {
	defer func() {
		if recovered := recover(); recovered != nil {
			ret = C.CString(fmt.Sprintf("panic in libbox_check_config: %v\n%s", recovered, string(debug.Stack())))
		}
	}()

	service, _, cancel, err := buildBox(C.GoString(configContent))
	if err != nil {
		return C.CString(err.Error())
	}
	cancel()
	err = service.Close()
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export libbox_set_paths
func libbox_set_paths(basePathRaw *C.char, workingPathRaw *C.char, tempPathRaw *C.char) *C.char {
	basePathMutex.Lock()
	defer basePathMutex.Unlock()

	basePath = C.GoString(basePathRaw)
	workingPath = C.GoString(workingPathRaw)
	tempPath = C.GoString(tempPathRaw)

	if basePath == "" || workingPath == "" || tempPath == "" {
		return C.CString("base_path, working_path and temp_path are required")
	}

	if err := os.MkdirAll(basePath, 0o755); err != nil {
		return C.CString(err.Error())
	}
	if err := os.MkdirAll(workingPath, 0o755); err != nil {
		return C.CString(err.Error())
	}
	if err := os.MkdirAll(tempPath, 0o755); err != nil {
		return C.CString(err.Error())
	}

	return nil
}

//export libbox_set_log_callback
func libbox_set_log_callback(callback C.libbox_log_callback, userData unsafe.Pointer) {
	logCallbackMutex.Lock()
	defer logCallbackMutex.Unlock()
	logCallback = callback
	logCallbackUserData = userData
}

//export libbox_version
func libbox_version() *C.char {
	return C.CString(buildVersion())
}

func buildVersion() string {
	return CBox.Version
}

//export libbox_free_string
func libbox_free_string(str *C.char) {
	C.free(unsafe.Pointer(str))
}

func main() {}
