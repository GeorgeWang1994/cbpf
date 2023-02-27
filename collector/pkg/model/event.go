package model

import "encoding/json"



type Event struct {
	Source Source
	// Timestamp in nanoseconds at which the event were collected.
	Timestamp uint64
	// Name of Kindling Event
	Name string
	// Category of Kindling Event, enum
	Category Category
	// Number of UserAttributes
	ParamsNumber uint16
	// User-defined Attributions of Kindling Event, now including latency for syscall.
	UserAttributes [8]KeyValue
	// Context includes Thread information and Fd information.
	Ctx Context
}

func (k *KindlingEvent) Reset() {
	k.Ctx.FdInfo.Num = 0
	k.Ctx.ThreadInfo.Pid = 0
}

func (m *KindlingEvent) GetSource() Source {
	if m != nil {
		return m.Source
	}
	return Source_SOURCE_UNKNOWN
}

func (m *KindlingEvent) GetTimestamp() uint64 {
	if m != nil {
		return m.Timestamp
	}
	return 0
}

func (m *KindlingEvent) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *KindlingEvent) GetCategory() Category {
	if m != nil {
		return m.Category
	}
	return Category_CAT_NONE
}

func (m *KindlingEvent) GetUserAttributes() *[8]KeyValue {
	return &m.UserAttributes
}

func (m *KindlingEvent) GetCtx() *Context {
	return &m.Ctx
}


func KeyValue struct {
	// Arguments' Name or Attributions' Name.
	Key string
	// Type of Value.
	ValueType ValueType
	// Value of Key in bytes, should be converted according to ValueType.
	Value []byte
}

func (m *KeyValue) GetKey() string {
	if m != nil {
		return m.Key
	}
	return ""
}

func (m *KeyValue) GetValueType() ValueType {
	if m != nil {
		return m.ValueType
	}
	return ValueType_NONE
}

func (m *KeyValue) GetValue() []byte {
	if m != nil {
		return m.Value
	}
	return nil
}

type Context struct {
	// Thread information corresponding to Kindling Event, optional.
	ThreadInfo Thread
	// Fd information corresponding to Kindling Event, optional.
	FdInfo Fd
}

func (m *Context) GetThreadInfo() *Thread {
	return &m.ThreadInfo
}

func (m *Context) GetFdInfo() *Fd {
	return &m.FdInfo
}

type Thread struct {
	// Process id of thread.
	Pid uint32
	// Thread/task id of thread.
	Tid uint32
	// User id of thread
	Uid uint32
	// Group id of thread
	Gid uint32
	// Command of thread.
	Comm string
	// ContainerId of thread
	ContainerId string
	// ContainerName of thread
	ContainerName string
}

func (m *Thread) GetPid() uint32 {
	if m != nil {
		return m.Pid
	}
	return 0
}

func (m *Thread) GetTid() uint32 {
	if m != nil {
		return m.Tid
	}
	return 0
}

func (m *Thread) GetUid() uint32 {
	if m != nil {
		return m.Uid
	}
	return 0
}

func (m *Thread) GetGid() uint32 {
	if m != nil {
		return m.Gid
	}
	return 0
}

func (m *Thread) GetComm() string {
	if m != nil {
		return m.Comm
	}
	return ""
}

func (m *Thread) GetContainerId() string {
	if m != nil {
		return m.ContainerId
	}
	return ""
}

func (m *Thread) GetContainerName() string {
	if m != nil {
		return m.ContainerName
	}
	return ""
}

type Fd struct {
	// FD number.
	Num int32
	// Type of FD in enum.
	TypeFd FDType
	// if FD is type of file
	Filename  string
	Directory string
	// if FD is type of ipv4 or ipv6
	Protocol L4Proto
	// repeated for ipv6, client_ip[0] for ipv4
	Role  bool
	Sip   []uint32
	Dip   []uint32
	Sport uint32
	Dport uint32
	// if FD is type of unix_sock
	// Source socket endpoint
	Source uint64
	// Destination socket endpoint
	Destination uint64
}

func (m *Fd) GetNum() int32 {
	if m != nil {
		return m.Num
	}
	return 0
}

func (m *Fd) GetTypeFd() FDType {
	if m != nil {
		return m.TypeFd
	}
	return FDType_FD_UNKNOWN
}

func (m *Fd) GetFilename() string {
	if m != nil {
		return m.Filename
	}
	return ""
}

func (m *Fd) GetDirectory() string {
	if m != nil {
		return m.Directory
	}
	return ""
}

func (m *Fd) GetProtocol() L4Proto {
	if m != nil {
		return m.Protocol
	}
	return L4Proto_UNKNOWN
}

func (m *Fd) GetRole() bool {
	if m != nil {
		return m.Role
	}
	return false
}

func (m *Fd) GetSip() []uint32 {
	if m != nil {
		return m.Sip
	}
	return nil
}

func (m *Fd) GetDip() []uint32 {
	if m != nil {
		return m.Dip
	}
	return nil
}

func (m *Fd) GetSport() uint32 {
	if m != nil {
		return m.Sport
	}
	return 0
}

func (m *Fd) GetDport() uint32 {
	if m != nil {
		return m.Dport
	}
	return 0
}

func (m *Fd) GetSource() uint64 {
	if m != nil {
		return m.Source
	}
	return 0
}

func (m *Fd) GetDestination() uint64 {
	if m != nil {
		return m.Destination
	}
	return 0
}

