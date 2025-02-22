package handlers

import (
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/NHAS/reverse_ssh/internal"
	"github.com/NHAS/reverse_ssh/pkg/logger"
	"golang.org/x/crypto/ssh"
)

type socksServer struct {
	listener net.Listener
	sshConn  ssh.Conn
	log      logger.Logger
}

func StartSocksServer(port int, sshConn ssh.Conn, log logger.Logger) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return fmt.Errorf("failed to start SOCKS server: %v", err)
	}

	server := &socksServer{
		listener: listener,
		sshConn:  sshConn,
		log:      log,
	}

	go server.serve()
	log.Info("Started SOCKS server on 0.0.0.0:%d", port)
	return nil
}

func (s *socksServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				s.log.Warning("SOCKS accept error: %v", err)
			}
			return
		}

		go s.handleConnection(conn)
	}
}

func (s *socksServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read SOCKS version
	version := make([]byte, 1)
	if _, err := io.ReadFull(conn, version); err != nil {
		s.log.Warning("Failed to read SOCKS version: %v", err)
		return
	}

	if version[0] != 5 {
		s.log.Warning("Unsupported SOCKS version: %d", version[0])
		return
	}

	// Read authentication methods
	nmethods := make([]byte, 1)
	if _, err := io.ReadFull(conn, nmethods); err != nil {
		s.log.Warning("Failed to read number of methods: %v", err)
		return
	}

	methods := make([]byte, nmethods[0])
	if _, err := io.ReadFull(conn, methods); err != nil {
		s.log.Warning("Failed to read methods: %v", err)
		return
	}

	// No authentication required
	conn.Write([]byte{5, 0})

	// Read the connection request
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		s.log.Warning("Failed to read request header: %v", err)
		return
	}

	if header[0] != 5 {
		s.log.Warning("Invalid SOCKS version in request: %d", header[0])
		return
	}

	if header[1] != 1 { // Only support CONNECT
		conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0}) // Command not supported
		return
	}

	var host string
	switch header[3] {
	case 1: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	case 3: // Domain name
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return
		}
		domain := make([]byte, length[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return
		}
		host = string(domain)
	case 4: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	default:
		conn.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0}) // Address type not supported
		return
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])

	// Open direct-tcpip channel to destination through SSH connection
	channel, reqs, err := s.sshConn.OpenChannel("direct-tcpip", ssh.Marshal(&internal.ChannelOpenDirectMsg{
		Raddr: host,
		Rport: uint32(port),
		Laddr: conn.RemoteAddr().(*net.TCPAddr).IP.String(),
		Lport: uint32(conn.RemoteAddr().(*net.TCPAddr).Port),
	}))
	if err != nil {
		s.log.Warning("Failed to open channel to %s:%d: %v", host, port, err)
		conn.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0}) // Host unreachable
		return
	}
	defer channel.Close()

	// Success response
	conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})

	go ssh.DiscardRequests(reqs)

	// Start bidirectional copy
	go func() {
		io.Copy(channel, conn)
		channel.CloseWrite()
	}()

	io.Copy(conn, channel)
} 