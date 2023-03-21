package model

import "encoding/json"

type ValueType int32

const (
	ValueType_NONE    ValueType = 0
	ValueType_INT8    ValueType = 1
	ValueType_INT16   ValueType = 2
	ValueType_INT32   ValueType = 3
	ValueType_INT64   ValueType = 4
	ValueType_UINT8   ValueType = 5
	ValueType_UINT16  ValueType = 6
	ValueType_UINT32  ValueType = 7
	ValueType_UINT64  ValueType = 8
	ValueType_CHARBUF ValueType = 9
	ValueType_BYTEBUF ValueType = 10
	ValueType_FLOAT   ValueType = 11
	ValueType_DOUBLE  ValueType = 12
	ValueType_BOOL    ValueType = 13
)

type Source int32

const (
	Source_SOURCE_UNKNOWN Source = 0
	Source_SYSCALL_ENTER  Source = 1
	Source_SYSCALL_EXIT   Source = 2
	Source_TRACEPOINT     Source = 3
	Source_KRPOBE         Source = 4
	Source_KRETPROBE      Source = 5
	Source_UPROBE         Source = 6
	Source_URETPROBE      Source = 7
)

// 事件来源
var Source_name = map[int32]string{
	0: "SOURCE_UNKNOWN",
	1: "SYSCALL_ENTER",
	2: "SYSCALL_EXIT",
	3: "TRACEPOINT",
	4: "KRPOBE",
	5: "KRETPROBE",
	6: "UPROBE",
	7: "URETPROBE",
}

func (x Source) String() string {
	return "SOURCE_UNKNOWN"
}

// 分类名称
type Category int32

const (
	Category_CAT_NONE      Category = 0
	Category_CAT_OTHER     Category = 1
	Category_CAT_FILE      Category = 2
	Category_CAT_NET       Category = 3
	Category_CAT_IPC       Category = 4
	Category_CAT_WAIT      Category = 5
	Category_CAT_SIGNAL    Category = 6
	Category_CAT_SLEEP     Category = 7
	Category_CAT_TIME      Category = 8
	Category_CAT_PROCESS   Category = 9
	Category_CAT_SCHEDULER Category = 10
	Category_CAT_MEMORY    Category = 11
	Category_CAT_USER      Category = 12
	Category_CAT_SYSTEM    Category = 13
)

var Category_name = map[int32]string{
	0:  "CAT_NONE",
	1:  "CAT_OTHER",
	2:  "CAT_FILE",
	3:  "CAT_NET",
	4:  "CAT_IPC",
	5:  "CAT_WAIT",
	6:  "CAT_SIGNAL",
	7:  "CAT_SLEEP",
	8:  "CAT_TIME",
	9:  "CAT_PROCESS",
	10: "CAT_SCHEDULER",
	11: "CAT_MEMORY",
	12: "CAT_USER",
	13: "CAT_SYSTEM",
}

var Category_value = map[string]int32{
	"CAT_NONE":      0,
	"CAT_OTHER":     1,
	"CAT_FILE":      2,
	"CAT_NET":       3,
	"CAT_IPC":       4,
	"CAT_WAIT":      5,
	"CAT_SIGNAL":    6,
	"CAT_SLEEP":     7,
	"CAT_TIME":      8,
	"CAT_PROCESS":   9,
	"CAT_SCHEDULER": 10,
	"CAT_MEMORY":    11,
	"CAT_USER":      12,
	"CAT_SYSTEM":    13,
}

// 值类型名臣定义
var ValueType_name = map[int32]string{
	0:  "NONE",
	1:  "INT8",
	2:  "INT16",
	3:  "INT32",
	4:  "INT64",
	5:  "UINT8",
	6:  "UINT16",
	7:  "UINT32",
	8:  "UINT64",
	9:  "CHARBUF",
	10: "BYTEBUF",
	11: "FLOAT",
	12: "DOUBLE",
	13: "BOOL",
}

var ValueType_value = map[string]int32{
	"NONE":    0,
	"INT8":    1,
	"INT16":   2,
	"INT32":   3,
	"INT64":   4,
	"UINT8":   5,
	"UINT16":  6,
	"UINT32":  7,
	"UINT64":  8,
	"CHARBUF": 9,
	"BYTEBUF": 10,
	"FLOAT":   11,
	"DOUBLE":  12,
	"BOOL":    13,
}

// File Descriptor type
type FDType int32

const (
	FDType_FD_UNKNOWN       FDType = 0
	FDType_FD_FILE          FDType = 1
	FDType_FD_DIRECTORY     FDType = 2
	FDType_FD_IPV4_SOCK     FDType = 3
	FDType_FD_IPV6_SOCK     FDType = 4
	FDType_FD_IPV4_SERVSOCK FDType = 5
	FDType_FD_IPV6_SERVSOCK FDType = 6
	FDType_FD_FIFO          FDType = 7
	FDType_FD_UNIX_SOCK     FDType = 8
	FDType_FD_EVENT         FDType = 9
	FDType_FD_UNSUPPORTED   FDType = 10
	FDType_FD_SIGNALFD      FDType = 11
	FDType_FD_EVENTPOLL     FDType = 12
	FDType_FD_INOTIFY       FDType = 13
	FDType_FD_TIMERFD       FDType = 14
	FDType_FD_NETLINK       FDType = 15
	FDType_FD_FILE_V2       FDType = 16
)

var FDType_name = map[int32]string{
	0:  "FD_UNKNOWN",
	1:  "FD_FILE",
	2:  "FD_DIRECTORY",
	3:  "FD_IPV4_SOCK",
	4:  "FD_IPV6_SOCK",
	5:  "FD_IPV4_SERVSOCK",
	6:  "FD_IPV6_SERVSOCK",
	7:  "FD_FIFO",
	8:  "FD_UNIX_SOCK",
	9:  "FD_EVENT",
	10: "FD_UNSUPPORTED",
	11: "FD_SIGNALFD",
	12: "FD_EVENTPOLL",
	13: "FD_INOTIFY",
	14: "FD_TIMERFD",
	15: "FD_NETLINK",
	16: "FD_FILE_V2",
}

var FDType_value = map[string]int32{
	"FD_UNKNOWN":       0,
	"FD_FILE":          1,
	"FD_DIRECTORY":     2,
	"FD_IPV4_SOCK":     3,
	"FD_IPV6_SOCK":     4,
	"FD_IPV4_SERVSOCK": 5,
	"FD_IPV6_SERVSOCK": 6,
	"FD_FIFO":          7,
	"FD_UNIX_SOCK":     8,
	"FD_EVENT":         9,
	"FD_UNSUPPORTED":   10,
	"FD_SIGNALFD":      11,
	"FD_EVENTPOLL":     12,
	"FD_INOTIFY":       13,
	"FD_TIMERFD":       14,
	"FD_NETLINK":       15,
	"FD_FILE_V2":       16,
}

type L4Proto int32

const (
	L4Proto_UNKNOWN L4Proto = 0
	L4Proto_TCP     L4Proto = 1
	L4Proto_UDP     L4Proto = 2
	L4Proto_ICMP    L4Proto = 3
	L4Proto_RAW     L4Proto = 4
)

var L4Proto_name = map[int32]string{
	0: "UNKNOWN",
	1: "TCP",
	2: "UDP",
	3: "ICMP",
	4: "RAW",
}

var L4Proto_value = map[string]int32{
	"UNKNOWN": 0,
	"TCP":     1,
	"UDP":     2,
	"ICMP":    3,
	"RAW":     4,
}

func (m *Event) String() string {
	data, _ := json.Marshal(&m)
	return string(data)
}

const (
	RequestCount         = "request_count"
	RequestTotalTime     = "request_total_time"
	ConnectTime          = "connect_time"
	RequestSentTime      = "request_sent_time"
	WaitingTtfbTime      = "waiting_ttfb_time"
	ContentDownloadTime  = "content_download_time"
	RequestTimeHistogram = "request_time_histogram"

	RequestIo  = "request_io"
	ResponseIo = "response_io"

	SpanInfo = "KSpanInfo"
)

const (
	ProtocolHttp  = "http"
	ProtocolHttp2 = "http2"
	ProtocolGrpc  = "grpc"
	ProtocolDubbo = "dubbo"
	ProtocolDns   = "dns"
	ProtocolKafka = "kafka"
	ProtocolMysql = "mysql"
)

const (
	ReadEvent     = "read"
	WriteEvent    = "write"
	ReadvEvent    = "readv"
	WritevEvent   = "writev"
	PReadEvent    = "pread"
	PWriteEvent   = "pwrite"
	PReadvEvent   = "preadv"
	PWritevEvent  = "pwritev"
	SendToEvent   = "sendto"
	RecvFromEvent = "recvfrom"
	SendMsgEvent  = "sendmsg"
	SendMMsgEvent = "sendmmsg"
	RecvMsgEvent  = "recvmsg"
	ConnectEvent  = "connect"

	TcpCloseEvent          = "tcp_close"
	TcpRcvEstablishedEvent = "tcp_rcv_established"
	TcpDropEvent           = "tcp_drop"
	TcpRetransmitSkbEvent  = "tcp_retransmit_skb"
	TcpConnectEvent        = "tcp_connect"
	TcpSetStateEvent       = "tcp_set_state"

	CpuEvent           = "cpu_event"
	JavaFutexInfo      = "java_futex_info"
	TransactionIdEvent = "apm_trace_id_event"
	SpanEvent          = "apm_span_event"
	OtherEvent         = "other"

	ProcessExitEvent = "procexit"
	GrpcUprobeEvent  = "grpc_uprobe"
	// NetRequestMetricGroupName is used for dataGroup generated from networkAnalyzer.
	NetRequestMetricGroupName = "net_request_metric_group"
	// SingleNetRequestMetricGroup stands for the dataGroup with abnormal status.
	SingleNetRequestMetricGroup = "single_net_request_metric_group"
	// AggregatedNetRequestMetricGroup stands for the dataGroup after aggregation.
	AggregatedNetRequestMetricGroup = "aggregated_net_request_metric_group"

	CameraEventGroupName = "camera_event_group"

	TcpMetricGroupName           = "tcp_metric_metric_group"
	TcpRttMetricGroupName        = "tcp_rtt_metric_group"
	TcpRetransmitMetricGroupName = "tcp_retransmit_metric_group"
	TcpDropMetricGroupName       = "tcp_drop_metric_group"
	NodeMetricGroupName          = "node_metric_metric_group"
	TcpConnectMetricGroupName    = "tcp_connect_metric_group"

	TcpConnectTotalMetric    = "kindling_tcp_connect_total"
	TcpConnectDurationMetric = "kindling_tcp_connect_duration_nanoseconds_total"
)
