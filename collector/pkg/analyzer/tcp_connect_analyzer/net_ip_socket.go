package tcp_connect_analyzer

type (
	SocketKey struct {
		LocalAddr string
		LocalPort uint64
		RemAddr   string
		RemPort   uint64
	}
)
