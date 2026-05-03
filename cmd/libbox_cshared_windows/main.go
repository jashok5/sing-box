package main

/*
#include <stdlib.h>
#include <stdint.h>

typedef void (*command_client_connected_cb)(size_t context);
typedef void (*command_client_disconnected_cb)(size_t context, const char* message);
typedef void (*command_client_log_cb)(size_t context, int level, const char* message);
typedef void (*libbox_log_callback)(void* user_data, int level, const char* message);

typedef struct {
	size_t Context;
	void* OnConnected;
	void* OnDisconnected;
	void* OnLog;
} CommandClientCallbacks;

static void call_command_client_connected(void* fn, size_t context) {
	if (fn != NULL) {
		((command_client_connected_cb) fn)(context);
	}
}

static void call_command_client_disconnected(void* fn, size_t context, const char* message) {
	if (fn != NULL) {
		((command_client_disconnected_cb) fn)(context, message);
	}
}

static void call_command_client_log(void* fn, size_t context, int level, const char* message) {
	if (fn != NULL) {
		((command_client_log_cb) fn)(context, level, message);
	}
}

static void invoke_log_callback(libbox_log_callback callback, void* user_data, int level, const char* message) {
	if (callback != NULL) {
		callback(user_data, level, message);
	}
}
*/
import "C"

import (
	stdjson "encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	lb "github.com/sagernet/sing-box/experimental/libbox"
)

var (
	commandServer *lb.CommandServer
	instanceMutex sync.Mutex

	nextHandle atomic.Int64
	handleMu   sync.RWMutex

	commandClientOptionsHandles = map[int64]*lb.CommandClientOptions{}
	commandClientHandles        = map[int64]*lb.CommandClient{}

	lastConfig    string
	lastConfigMu  sync.RWMutex

	logCallback         C.libbox_log_callback
	logCallbackUserData unsafe.Pointer
	logCallbackMu       sync.RWMutex
	logClient           *lb.CommandClient
	logClientHandle     int64
)

type emptyStringIterator struct{}

func (i *emptyStringIterator) Len() int32 {
	return 0
}

func (i *emptyStringIterator) HasNext() bool {
	return false
}

func (i *emptyStringIterator) Next() string {
	return ""
}

type stringArrayIterator struct {
	values []string
}

func (i *stringArrayIterator) Len() int32 {
	return int32(len(i.values))
}

func (i *stringArrayIterator) HasNext() bool {
	return len(i.values) > 0
}

func (i *stringArrayIterator) Next() string {
	if len(i.values) == 0 {
		return ""
	}
	next := i.values[0]
	i.values = i.values[1:]
	return next
}

type emptyNetworkInterfaceIterator struct{}

func (i *emptyNetworkInterfaceIterator) HasNext() bool {
	return false
}

func (i *emptyNetworkInterfaceIterator) Next() *lb.NetworkInterface {
	return nil
}

type networkInterfaceIterator struct {
	values []*lb.NetworkInterface
}

func (i *networkInterfaceIterator) HasNext() bool {
	return len(i.values) > 0
}

func (i *networkInterfaceIterator) Next() *lb.NetworkInterface {
	if len(i.values) == 0 {
		return nil
	}
	next := i.values[0]
	i.values = i.values[1:]
	return next
}

type csharedPlatformInterface struct{}

func (p *csharedPlatformInterface) LocalDNSTransport() lb.LocalDNSTransport {
	return nil
}

func (p *csharedPlatformInterface) UsePlatformAutoDetectInterfaceControl() bool {
	return false
}

func (p *csharedPlatformInterface) AutoDetectInterfaceControl(fd int32) error {
	return nil
}

func (p *csharedPlatformInterface) OpenTun(options lb.TunOptions) (int32, error) {
	return -1, os.ErrInvalid
}

func (p *csharedPlatformInterface) UseProcFS() bool {
	return false
}

func (p *csharedPlatformInterface) FindConnectionOwner(ipProtocol int32, sourceAddress string, sourcePort int32, destinationAddress string, destinationPort int32) (*lb.ConnectionOwner, error) {
	return nil, os.ErrInvalid
}

func (p *csharedPlatformInterface) StartDefaultInterfaceMonitor(listener lb.InterfaceUpdateListener) error {
	if listener == nil {
		return nil
	}
	defaultName, defaultIndex, err := findDefaultInterface()
	if err != nil {
		listener.UpdateDefaultInterface("", -1, false, false)
		return nil
	}
	listener.UpdateDefaultInterface(defaultName, defaultIndex, false, false)
	return nil
}

func (p *csharedPlatformInterface) CloseDefaultInterfaceMonitor(listener lb.InterfaceUpdateListener) error {
	return nil
}

func (p *csharedPlatformInterface) GetInterfaces() (lb.NetworkInterfaceIterator, error) {
	netInterfaces, err := net.Interfaces()
	if err != nil {
		return &emptyNetworkInterfaceIterator{}, nil
	}

	result := make([]*lb.NetworkInterface, 0, len(netInterfaces))
	for _, iface := range netInterfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		cidrs := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			cidr := normalizeInterfaceCIDR(addr)
			if cidr == "" {
				continue
			}
			cidrs = append(cidrs, cidr)
		}
		if len(cidrs) == 0 {
			continue
		}

		result = append(result, &lb.NetworkInterface{
			Index:     int32(iface.Index),
			MTU:       int32(iface.MTU),
			Name:      iface.Name,
			Addresses: &stringArrayIterator{values: cidrs},
			Flags:     int32(iface.Flags),
			Type:      inferInterfaceType(iface.Name),
			DNSServer: &emptyStringIterator{},
			Metered:   false,
		})
	}

	if len(result) == 0 {
		return &emptyNetworkInterfaceIterator{}, nil
	}

	return &networkInterfaceIterator{values: result}, nil
}

func (p *csharedPlatformInterface) UnderNetworkExtension() bool {
	return false
}

func (p *csharedPlatformInterface) IncludeAllNetworks() bool {
	return false
}

func (p *csharedPlatformInterface) ReadWIFIState() *lb.WIFIState {
	return nil
}

func (p *csharedPlatformInterface) SystemCertificates() lb.StringIterator {
	return &emptyStringIterator{}
}

func (p *csharedPlatformInterface) ClearDNSCache() {
}

func (p *csharedPlatformInterface) SendNotification(notification *lb.Notification) error {
	return nil
}

func (p *csharedPlatformInterface) DisablePlatformInterface() bool {
	return true
}

func inferInterfaceType(name string) int32 {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "wi-fi") || strings.Contains(lower, "wifi") || strings.Contains(lower, "wlan") {
		return lb.InterfaceTypeWIFI
	}
	if strings.Contains(lower, "ethernet") || strings.HasPrefix(lower, "eth") {
		return lb.InterfaceTypeEthernet
	}
	if strings.Contains(lower, "cell") || strings.Contains(lower, "wwan") || strings.Contains(lower, "mobile") || strings.Contains(lower, "lte") {
		return lb.InterfaceTypeCellular
	}
	return lb.InterfaceTypeOther
}

func normalizeInterfaceCIDR(addr net.Addr) string {
	ipNet, ok := addr.(*net.IPNet)
	if !ok || ipNet == nil {
		return ""
	}
	ones, bits := ipNet.Mask.Size()
	if ones < 0 || bits <= 0 {
		return ""
	}
	netAddr, ok := netip.AddrFromSlice(ipNet.IP)
	if !ok {
		return ""
	}
	netAddr = netAddr.Unmap()
	return netip.PrefixFrom(netAddr, ones).String()
}

func findDefaultInterface() (string, int32, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", -1, err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, addrErr := iface.Addrs()
		if addrErr != nil || len(addrs) == 0 {
			continue
		}
		return iface.Name, int32(iface.Index), nil
	}

	return "", -1, os.ErrNotExist
}

type csharedCommandServerHandler struct{}

type csharedCommandClientCallbackHandler struct {
	context        C.size_t
	onConnected    unsafe.Pointer
	onDisconnected unsafe.Pointer
	onLog          unsafe.Pointer
}

func (h *csharedCommandClientCallbackHandler) Connected() {
	if h.onConnected != nil {
		C.call_command_client_connected(h.onConnected, h.context)
	}
}

func (h *csharedCommandClientCallbackHandler) Disconnected(message string) {
	if h.onDisconnected == nil {
		return
	}
	cMessage := C.CString(message)
	defer C.free(unsafe.Pointer(cMessage))
	C.call_command_client_disconnected(h.onDisconnected, h.context, cMessage)
}

func (h *csharedCommandClientCallbackHandler) SetDefaultLogLevel(level int32) {}

func (h *csharedCommandClientCallbackHandler) ClearLogs() {}

func (h *csharedCommandClientCallbackHandler) WriteLogs(messageList lb.LogIterator) {
	if h.onLog == nil || messageList == nil {
		return
	}
	for messageList.HasNext() {
		next := messageList.Next()
		if next == nil {
			continue
		}
		cMessage := C.CString(next.Message)
		C.call_command_client_log(h.onLog, h.context, C.int(next.Level), cMessage)
		C.free(unsafe.Pointer(cMessage))
	}
}

func (h *csharedCommandClientCallbackHandler) WriteStatus(message *lb.StatusMessage) {}

func (h *csharedCommandClientCallbackHandler) WriteGroups(message lb.OutboundGroupIterator) {}

func (h *csharedCommandClientCallbackHandler) InitializeClashMode(modeList lb.StringIterator, currentMode string) {
}

func (h *csharedCommandClientCallbackHandler) UpdateClashMode(newMode string) {}

func (h *csharedCommandClientCallbackHandler) WriteConnectionEvents(events *lb.ConnectionEvents) {}

func (h *csharedCommandServerHandler) ServiceStop() error {
	instanceMutex.Lock()
	defer instanceMutex.Unlock()
	if commandServer == nil {
		return nil
	}
	return commandServer.CloseService()
}

func (h *csharedCommandServerHandler) ServiceReload() error {
	return errors.New("service reload not supported in cshared handler")
}

func (h *csharedCommandServerHandler) GetSystemProxyStatus() (*lb.SystemProxyStatus, error) {
	return &lb.SystemProxyStatus{Available: false, Enabled: false}, nil
}

func (h *csharedCommandServerHandler) SetSystemProxyEnabled(enabled bool) error {
	return nil
}

func (h *csharedCommandServerHandler) WriteDebugMessage(message string) {
}

type csharedLogCallbackHandler struct{}

func (h *csharedLogCallbackHandler) Connected() {}

func (h *csharedLogCallbackHandler) Disconnected(message string) {}

func (h *csharedLogCallbackHandler) SetDefaultLogLevel(level int32) {}

func (h *csharedLogCallbackHandler) ClearLogs() {}

func (h *csharedLogCallbackHandler) WriteLogs(messageList lb.LogIterator) {
	logCallbackMu.RLock()
	callback := logCallback
	userData := logCallbackUserData
	logCallbackMu.RUnlock()
	if callback == nil || messageList == nil {
		return
	}
	for messageList.HasNext() {
		next := messageList.Next()
		if next == nil {
			continue
		}
		cMessage := C.CString(next.Message)
		C.invoke_log_callback(callback, userData, C.int(next.Level), cMessage)
		C.free(unsafe.Pointer(cMessage))
	}
}

func (h *csharedLogCallbackHandler) WriteStatus(message *lb.StatusMessage) {}

func (h *csharedLogCallbackHandler) WriteGroups(message lb.OutboundGroupIterator) {}

func (h *csharedLogCallbackHandler) InitializeClashMode(modeList lb.StringIterator, currentMode string) {}

func (h *csharedLogCallbackHandler) UpdateClashMode(newMode string) {}

func (h *csharedLogCallbackHandler) WriteConnectionEvents(events *lb.ConnectionEvents) {}

func init() {
	nextHandle.Store(1000)
}

func cError(err error) *C.char {
	if err == nil {
		return nil
	}
	return C.CString(err.Error())
}

func cStringOrEmpty(value *C.char) string {
	if value == nil {
		return ""
	}
	return C.GoString(value)
}

func setOutCString(out **C.char, value string) error {
	if out == nil {
		return errors.New("out pointer is nil")
	}
	*out = C.CString(value)
	return nil
}

func nextID() int64 {
	return nextHandle.Add(1)
}

func getCommandClientOptions(handle C.longlong) (*lb.CommandClientOptions, error) {
	handleMu.RLock()
	defer handleMu.RUnlock()
	value := commandClientOptionsHandles[int64(handle)]
	if value == nil {
		return nil, errors.New("invalid command client options handle")
	}
	return value, nil
}

func getCommandClient(handle C.longlong) (*lb.CommandClient, error) {
	handleMu.RLock()
	defer handleMu.RUnlock()
	value := commandClientHandles[int64(handle)]
	if value == nil {
		return nil, errors.New("invalid command client handle")
	}
	return value, nil
}

func connectLogClient() {
	logCallbackMu.RLock()
	callback := logCallback
	logCallbackMu.RUnlock()
	if callback == nil || commandServer == nil {
		return
	}

	disconnectLogClientLocked()

	options := &lb.CommandClientOptions{}
	options.AddCommand(int32(lb.CommandLog))
	client := lb.NewCommandClient(&csharedLogCallbackHandler{}, options)
	handle := nextID()
	handleMu.Lock()
	commandClientHandles[handle] = client
	handleMu.Unlock()
	logClient = client
	logClientHandle = handle
	go func() {
		_ = client.Connect()
	}()
}

func disconnectLogClientLocked() {
	if logClient != nil {
		_ = logClient.Disconnect()
		handleMu.Lock()
		delete(commandClientHandles, logClientHandle)
		handleMu.Unlock()
		logClient = nil
	}
}

func disconnectLogClient() {
	disconnectLogClientLocked()
}

func startService(configStr string) error {
	handler := &csharedCommandServerHandler{}
	platformInterface := &csharedPlatformInterface{}
	server, err := lb.NewCommandServer(handler, platformInterface)
	if err != nil {
		return err
	}

	err = server.Start()
	if err != nil {
		server.Close()
		return err
	}

	err = server.StartOrReloadService(configStr, &lb.OverrideOptions{})
	if err != nil {
		server.Close()
		return err
	}

	commandServer = server
	connectLogClient()
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

	if commandServer != nil {
		return C.CString("service already running")
	}

	configStr := C.GoString(configContent)

	lastConfigMu.Lock()
	lastConfig = configStr
	lastConfigMu.Unlock()

	err := startService(configStr)
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
func libbox_stop() *C.char {
	instanceMutex.Lock()
	defer instanceMutex.Unlock()

	if commandServer == nil {
		return C.CString("service not running")
	}

	disconnectLogClient()

	err := commandServer.CloseService()
	commandServer.Close()
	commandServer = nil

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

	if commandServer == nil {
		return C.CString("service not running")
	}

	configStr := C.GoString(configContent)

	lastConfigMu.Lock()
	lastConfig = configStr
	lastConfigMu.Unlock()

	disconnectLogClientLocked()

	err := commandServer.StartOrReloadService(configStr, &lb.OverrideOptions{})
	if err != nil {
		return C.CString(err.Error())
	}

	connectLogClient()
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

	lastConfigMu.Lock()
	lastConfig = configStr
	lastConfigMu.Unlock()

	if commandServer != nil {
		disconnectLogClientLocked()

		err := commandServer.StartOrReloadService(configStr, &lb.OverrideOptions{})
		if err != nil {
			return C.CString(err.Error())
		}

		connectLogClient()
		return nil
	}

	err := startService(configStr)
	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export libbox_is_running
func libbox_is_running() C.int {
	instanceMutex.Lock()
	defer instanceMutex.Unlock()
	if commandServer == nil {
		return 0
	}
	return 1
}

//export libbox_free_string
func libbox_free_string(str *C.char) {
	C.free(unsafe.Pointer(str))
}

//export libbox_setup
func libbox_setup(optionsJSON *C.char) *C.char {
	var options lb.SetupOptions
	err := stdjson.Unmarshal([]byte(cStringOrEmpty(optionsJSON)), &options)
	if err != nil {
		return cError(err)
	}
	return cError(lb.Setup(&options))
}

//export libbox_set_paths
func libbox_set_paths(basePathRaw *C.char, workingPathRaw *C.char, tempPathRaw *C.char) *C.char {
	cJSON := C.CString(fmt.Sprintf(
		`{"BasePath":%q,"WorkingPath":%q,"TempPath":%q}`,
		C.GoString(basePathRaw), C.GoString(workingPathRaw), C.GoString(tempPathRaw),
	))
	defer C.free(unsafe.Pointer(cJSON))
	return libbox_setup(cJSON)
}

//export libbox_set_log_callback
func libbox_set_log_callback(callback C.libbox_log_callback, userData unsafe.Pointer) {
	logCallbackMu.Lock()
	hadCallback := logCallback != nil
	logCallback = callback
	logCallbackUserData = userData
	logCallbackMu.Unlock()

	instanceMutex.Lock()
	defer instanceMutex.Unlock()

	if callback == nil && hadCallback {
		disconnectLogClientLocked()
	} else if callback != nil && commandServer != nil {
		connectLogClient()
	}
}

//export libbox_set_locale
func libbox_set_locale(localeID *C.char) {
	lb.SetLocale(cStringOrEmpty(localeID))
}

//export libbox_version
func libbox_version(out **C.char) *C.char {
	return cError(setOutCString(out, lb.Version()))
}

//export libbox_check_config
func libbox_check_config(configContent *C.char) *C.char {
	return cError(lb.CheckConfig(cStringOrEmpty(configContent)))
}

//export libbox_format_config
func libbox_format_config(configContent *C.char, out **C.char) *C.char {
	formatted, err := lb.FormatConfig(cStringOrEmpty(configContent))
	if err != nil {
		return cError(err)
	}
	if formatted == nil {
		return cError(errors.New("formatted config is nil"))
	}
	return cError(setOutCString(out, formatted.Value))
}

//export libbox_compare_semver
func libbox_compare_semver(left *C.char, right *C.char) C.int {
	if lb.CompareSemver(cStringOrEmpty(left), cStringOrEmpty(right)) {
		return 1
	}
	return 0
}

//export libbox_proxy_display_type
func libbox_proxy_display_type(proxyType *C.char, out **C.char) *C.char {
	return cError(setOutCString(out, lb.ProxyDisplayType(cStringOrEmpty(proxyType))))
}

//export libbox_format_bytes
func libbox_format_bytes(length C.longlong, out **C.char) *C.char {
	return cError(setOutCString(out, lb.FormatBytes(int64(length))))
}

//export libbox_format_memory_bytes
func libbox_format_memory_bytes(length C.longlong, out **C.char) *C.char {
	return cError(setOutCString(out, lb.FormatMemoryBytes(int64(length))))
}

//export libbox_format_duration
func libbox_format_duration(durationMs C.longlong, out **C.char) *C.char {
	return cError(setOutCString(out, lb.FormatDuration(int64(durationMs))))
}

//export libbox_available_port
func libbox_available_port(startPort C.int, out *C.int) *C.char {
	if out == nil {
		return cError(errors.New("out pointer is nil"))
	}
	port, err := lb.AvailablePort(int32(startPort))
	if err != nil {
		return cError(err)
	}
	*out = C.int(port)
	return nil
}

//export libbox_command_log
func libbox_command_log() C.int {
	return C.int(lb.CommandLog)
}

//export libbox_command_status
func libbox_command_status() C.int {
	return C.int(lb.CommandStatus)
}

//export libbox_command_group
func libbox_command_group() C.int {
	return C.int(lb.CommandGroup)
}

//export libbox_command_clash_mode
func libbox_command_clash_mode() C.int {
	return C.int(lb.CommandClashMode)
}

//export libbox_command_connections
func libbox_command_connections() C.int {
	return C.int(lb.CommandConnections)
}

//export libbox_command_client_options_new
func libbox_command_client_options_new() C.longlong {
	handle := nextID()
	handleMu.Lock()
	commandClientOptionsHandles[handle] = &lb.CommandClientOptions{}
	handleMu.Unlock()
	return C.longlong(handle)
}

//export libbox_command_client_options_free
func libbox_command_client_options_free(handle C.longlong) {
	handleMu.Lock()
	delete(commandClientOptionsHandles, int64(handle))
	handleMu.Unlock()
}

//export libbox_command_client_options_add_command
func libbox_command_client_options_add_command(handle C.longlong, command C.int) *C.char {
	options, err := getCommandClientOptions(handle)
	if err != nil {
		return cError(err)
	}
	options.AddCommand(int32(command))
	return nil
}

//export libbox_command_client_options_set_status_interval
func libbox_command_client_options_set_status_interval(handle C.longlong, interval C.longlong) *C.char {
	options, err := getCommandClientOptions(handle)
	if err != nil {
		return cError(err)
	}
	options.StatusInterval = int64(interval)
	return nil
}

//export libbox_command_client_new
func libbox_command_client_new(optionsHandle C.longlong, outHandle *C.longlong) *C.char {
	if outHandle == nil {
		return cError(errors.New("out handle pointer is nil"))
	}
	options, err := getCommandClientOptions(optionsHandle)
	if err != nil {
		return cError(err)
	}
	client := lb.NewCommandClient(nil, options)
	handle := nextID()
	handleMu.Lock()
	commandClientHandles[handle] = client
	handleMu.Unlock()
	*outHandle = C.longlong(handle)
	return nil
}

//export libbox_command_client_new_with_callbacks
func libbox_command_client_new_with_callbacks(optionsHandle C.longlong, callbacks *C.CommandClientCallbacks, outHandle *C.longlong) *C.char {
	if outHandle == nil {
		return cError(errors.New("out handle pointer is nil"))
	}
	options, err := getCommandClientOptions(optionsHandle)
	if err != nil {
		return cError(err)
	}
	handler := &csharedCommandClientCallbackHandler{}
	if callbacks != nil {
		handler.context = callbacks.Context
		handler.onConnected = callbacks.OnConnected
		handler.onDisconnected = callbacks.OnDisconnected
		handler.onLog = callbacks.OnLog
	}
	client := lb.NewCommandClient(handler, options)
	handle := nextID()
	handleMu.Lock()
	commandClientHandles[handle] = client
	handleMu.Unlock()
	*outHandle = C.longlong(handle)
	return nil
}

//export libbox_command_client_new_standalone
func libbox_command_client_new_standalone(outHandle *C.longlong) *C.char {
	if outHandle == nil {
		return cError(errors.New("out handle pointer is nil"))
	}
	client := lb.NewStandaloneCommandClient()
	handle := nextID()
	handleMu.Lock()
	commandClientHandles[handle] = client
	handleMu.Unlock()
	*outHandle = C.longlong(handle)
	return nil
}

//export libbox_command_client_free
func libbox_command_client_free(handle C.longlong) {
	handleMu.Lock()
	client := commandClientHandles[int64(handle)]
	delete(commandClientHandles, int64(handle))
	handleMu.Unlock()
	if client != nil {
		_ = client.Disconnect()
	}
}

//export libbox_command_client_connect
func libbox_command_client_connect(handle C.longlong) *C.char {
	client, err := getCommandClient(handle)
	if err != nil {
		return cError(err)
	}
	return cError(client.Connect())
}

//export libbox_command_client_disconnect
func libbox_command_client_disconnect(handle C.longlong) *C.char {
	client, err := getCommandClient(handle)
	if err != nil {
		return cError(err)
	}
	return cError(client.Disconnect())
}

//export libbox_command_client_select_outbound
func libbox_command_client_select_outbound(handle C.longlong, groupTag *C.char, outboundTag *C.char) *C.char {
	client, err := getCommandClient(handle)
	if err != nil {
		return cError(err)
	}
	return cError(client.SelectOutbound(cStringOrEmpty(groupTag), cStringOrEmpty(outboundTag)))
}

//export libbox_command_client_url_test
func libbox_command_client_url_test(handle C.longlong, groupTag *C.char) *C.char {
	client, err := getCommandClient(handle)
	if err != nil {
		return cError(err)
	}
	return cError(client.URLTest(cStringOrEmpty(groupTag)))
}

//export libbox_command_client_set_clash_mode
func libbox_command_client_set_clash_mode(handle C.longlong, mode *C.char) *C.char {
	client, err := getCommandClient(handle)
	if err != nil {
		return cError(err)
	}
	return cError(client.SetClashMode(cStringOrEmpty(mode)))
}

//export libbox_command_client_service_reload
func libbox_command_client_service_reload(handle C.longlong) *C.char {
	client, err := getCommandClient(handle)
	if err != nil {
		return cError(err)
	}
	return cError(client.ServiceReload())
}

//export libbox_command_client_service_close
func libbox_command_client_service_close(handle C.longlong) *C.char {
	client, err := getCommandClient(handle)
	if err != nil {
		return cError(err)
	}
	return cError(client.ServiceClose())
}

//export libbox_command_client_get_system_proxy_status_json
func libbox_command_client_get_system_proxy_status_json(handle C.longlong, out **C.char) *C.char {
	client, err := getCommandClient(handle)
	if err != nil {
		return cError(err)
	}
	status, err := client.GetSystemProxyStatus()
	if err != nil {
		return cError(err)
	}
	jsonBytes, err := stdjson.Marshal(status)
	if err != nil {
		return cError(err)
	}
	return cError(setOutCString(out, string(jsonBytes)))
}

//export libbox_command_client_set_system_proxy_enabled
func libbox_command_client_set_system_proxy_enabled(handle C.longlong, enabled C.int) *C.char {
	client, err := getCommandClient(handle)
	if err != nil {
		return cError(err)
	}
	return cError(client.SetSystemProxyEnabled(enabled != 0))
}

//export libbox_command_client_get_deprecated_notes_json
func libbox_command_client_get_deprecated_notes_json(handle C.longlong, out **C.char) *C.char {
	client, err := getCommandClient(handle)
	if err != nil {
		return cError(err)
	}
	notes, err := client.GetDeprecatedNotes()
	if err != nil {
		return cError(err)
	}
	var result []map[string]string
	for notes != nil && notes.HasNext() {
		next := notes.Next()
		if next == nil {
			continue
		}
		result = append(result, map[string]string{
			"description":    next.Description,
			"migration_link": next.MigrationLink,
		})
	}
	jsonBytes, err := stdjson.Marshal(result)
	if err != nil {
		return cError(err)
	}
	return cError(setOutCString(out, string(jsonBytes)))
}

//export libbox_command_client_get_started_at
func libbox_command_client_get_started_at(handle C.longlong, out *C.longlong) *C.char {
	if out == nil {
		return cError(errors.New("out pointer is nil"))
	}
	client, err := getCommandClient(handle)
	if err != nil {
		return cError(err)
	}
	startedAt, err := client.GetStartedAt()
	if err != nil {
		return cError(err)
	}
	*out = C.longlong(startedAt)
	return nil
}

func main() {}
