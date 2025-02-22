package handlers

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/NHAS/reverse_ssh/internal"
	"github.com/NHAS/reverse_ssh/internal/server/users"
	"github.com/NHAS/reverse_ssh/pkg/logger"
	"golang.org/x/crypto/ssh"
)

func DirectTCPIP(_ string, _ *users.User, newChannel ssh.NewChannel, log logger.Logger) {
	var msg internal.ChannelOpenDirectMsg
	if err := ssh.Unmarshal(newChannel.ExtraData(), &msg); err != nil {
		log.Warning("Failed to unmarshal direct-tcpip data: %v", err)
		newChannel.Reject(ssh.ConnectionFailed, "failed to unmarshal channel data")
		return
	}

	// Connect to the target host
	dest := fmt.Sprintf("%s:%d", msg.Raddr, msg.Rport)
	targetConn, err := net.DialTimeout("tcp", dest, 10*time.Second)
	if err != nil {
		log.Warning("Failed to connect to %s: %v", dest, err)
		newChannel.Reject(ssh.ConnectionFailed, fmt.Sprintf("failed to connect to %s", dest))
		return
	}
	defer targetConn.Close()

	// Accept the channel
	ch, reqs, err := newChannel.Accept()
	if err != nil {
		log.Warning("Failed to accept channel: %v", err)
		return
	}
	defer ch.Close()

	// Discard channel requests
	go ssh.DiscardRequests(reqs)

	// Start bidirectional copy
	go func() {
		io.Copy(ch, targetConn)
		ch.CloseWrite()
	}()

	io.Copy(targetConn, ch)
} 