package tcp_connect_analyzer

import (
	"collector/pkg/model"
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
)

// ConnectMonitor reads in events related to TCP connect operations and updates its
// status to record the connection procedure.
// This is not thread safe to use.
type ConnectMonitor struct {
	connMap        map[ConnKey]*ConnectionStats
	statesResource StatesResource
	hostProcPath   string
	logger         *zap.Logger
}

const HostProc = "HOST_PROC_PATH"

func NewConnectMonitor(logger *zap.Logger) *ConnectMonitor {
	path, ok := os.LookupEnv(HostProc)
	if !ok {
		path = "/proc"
	}
	return &ConnectMonitor{
		connMap:        make(map[ConnKey]*ConnectionStats),
		statesResource: createStatesResource(),
		hostProcPath:   path,
		logger:         logger,
	}
}

// 读取连接退出事件
func (c *ConnectMonitor) ReadInConnectExitSyscall(event *model.Event) (*ConnectionStats, error) {
	retValue := event.GetUserAttribute("res")
	if retValue == nil {
		return nil, fmt.Errorf("res of connect_exit is nil")
	}
	retValueInt := retValue.GetIntValue()

	connKey := ConnKey{
		SrcIP:   event.GetSip(),
		SrcPort: event.GetSport(),
		DstIP:   event.GetDip(),
		DstPort: event.GetDport(),
	}
	if ce := c.logger.Check(zapcore.DebugLevel, "Receive connect_exit event:"); ce != nil {
		ce.Write(
			zap.String("ConnKey", connKey.String()),
			zap.Int64("retValue", retValueInt),
		)
	}

	connStats, ok := c.connMap[connKey]
	if !ok {
		// Maybe the connStats have been closed by tcp_set_state_from_established event.
		// We don't care about it.
		return nil, nil
	}
	// "connect_exit" comes to analyzer after "tcp_connect"
	connStats.EndTimestamp = event.Timestamp
	connStats.Pid = event.GetPid()
	connStats.Comm = event.GetComm()
	connStats.ContainerId = event.GetContainerId()
	var eventType EventType
	if retValueInt == 0 {
		eventType = connectExitSyscallSuccess
	} else if isNotErrorReturnCode(retValueInt) {
		eventType = connectExitSyscallNotConcern
	} else {
		eventType = connectExitSyscallFailure
		connStats.Code = int(retValueInt)
	}
	return connStats.StateMachine.ReceiveEvent(eventType, c.connMap)
}

// 读取发送请求事件
func (c *ConnectMonitor) ReadSendRequestSyscall(event *model.Event) (*ConnectionStats, error) {
	// The events without sip/sport/dip/dport have been filtered outside this method.
	connKey := ConnKey{
		SrcIP:   event.GetSip(),
		SrcPort: event.GetSport(),
		DstIP:   event.GetDip(),
		DstPort: event.GetDport(),
	}
	if ce := c.logger.Check(zapcore.DebugLevel, "Receive sendRequestSyscall event:"); ce != nil {
		ce.Write(
			zap.String("ConnKey", connKey.String()),
			zap.String("eventName", event.Name),
		)
	}

	connStats, ok := c.connMap[connKey]
	if !ok {
		return nil, nil
	}
	connStats.Pid = event.GetPid()
	connStats.Comm = event.GetComm()
	connStats.ContainerId = event.GetContainerId()
	return connStats.StateMachine.ReceiveEvent(sendRequestSyscall, c.connMap)
}

func isNotErrorReturnCode(code int64) bool {
	return code == einprogress || code == eintr || code == eisconn || code == ealready
}

// 读取tcp连接事件
func (c *ConnectMonitor) ReadInTcpConnect(event *model.Event) (*ConnectionStats, error) {
	connKey, err := getConnKeyForTcpConnect(event)
	if err != nil {
		return nil, err
	}
	retValue := event.GetUserAttribute("retval")
	if retValue == nil {
		return nil, fmt.Errorf("retval of tcp_connect is nil")
	}
	retValueInt := retValue.GetUintValue()

	if ce := c.logger.Check(zapcore.DebugLevel, "Receive tcp_connect event:"); ce != nil {
		ce.Write(
			zap.String("ConnKey", connKey.String()),
			zap.Uint64("retValue", retValueInt),
		)
	}

	var eventType EventType
	if retValueInt == 0 {
		eventType = tcpConnectNoError
	} else {
		eventType = tcpConnectError
	}

	connStats, ok := c.connMap[connKey]
	if !ok {
		// "tcp_connect" comes to analyzer before "connect_exit"
		connStats = &ConnectionStats{
			ConnKey:          connKey,
			InitialTimestamp: event.Timestamp,
			EndTimestamp:     event.Timestamp,
			Code:             int(retValueInt),
		}
		connStats.StateMachine = NewStateMachine(Inprogress, c.statesResource, connStats)
		c.connMap[connKey] = connStats
	} else {
		// Not possible to enter this branch
		c.logger.Info("Receive another unexpected tcp_connect event", zap.String("connKey", connKey.String()))
		connStats.EndTimestamp = event.Timestamp
		connStats.Code = int(retValueInt)
	}
	return connStats.StateMachine.ReceiveEvent(eventType, c.connMap)
}

func getConnKeyForTcpConnect(event *model.Event) (ConnKey, error) {
	var sIpString string
	var sPortUint uint64
	var dIpString string
	var dPortUint uint64
	sIp := event.GetUserAttribute("sip")
	if sIp != nil {
		sIpString = model.IPLong2String(uint32(sIp.GetUintValue()))
	}
	sPort := event.GetUserAttribute("sport")
	if sPort != nil {
		sPortUint = sPort.GetUintValue()
	}
	dIp := event.GetUserAttribute("dip")
	if dIp != nil {
		dIpString = model.IPLong2String(uint32(dIp.GetUintValue()))
	}
	dPort := event.GetUserAttribute("dport")
	if dPort != nil {
		dPortUint = dPort.GetUintValue()
	}

	if sIp == nil || sPort == nil || dIp == nil || dPort == nil {
		return ConnKey{}, fmt.Errorf("some fields are nil for event %s. srcIp=%v, srcPort=%v, "+
			"dstIp=%v, dstPort=%v", event.Name, sIpString, sPortUint, dIpString, dPortUint)
	}

	connKey := ConnKey{
		SrcIP:   sIpString,
		SrcPort: uint32(sPortUint),
		DstIP:   dIpString,
		DstPort: uint32(dPortUint),
	}
	return connKey, nil
}
