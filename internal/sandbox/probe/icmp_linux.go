// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

// icmpEcho sends an echo request to ip from an unprivileged ICMP socket,
// which the probe container's own group may open (its ping_group_range; no
// capability), and waits for the reply: the network must drop it (HR-122).
func icmpEcho(ctx context.Context, ip net.IP) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
	if err != nil {
		return fmt.Errorf("ICMP socket: %w", err)
	}
	defer func() { _ = syscall.Close(fd) }()
	// The kernel sets the identifier and the checksum of a ping socket.
	msg := append([]byte{8, 0, 0, 0, 0, 0, 0, 1}, "pantherclaw-probe"...)
	sa := &syscall.SockaddrInet4{}
	copy(sa.Addr[:], ip)
	if err := syscall.Sendto(fd, msg, 0, sa); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	deadline := time.Now().Add(dialTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	tv := syscall.NsecToTimeval(time.Until(deadline).Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	buf := make([]byte, 1500)
	for time.Now().Before(deadline) {
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return fmt.Errorf("no echo reply: %w", err)
		}
		if src, ok := from.(*syscall.SockaddrInet4); ok && net.IP(src.Addr[:]).Equal(ip) && n >= 8 && buf[0] == 0 {
			return nil
		}
	}
	return errors.New("no echo reply")
}
