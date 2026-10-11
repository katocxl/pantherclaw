// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package probe

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

// pingSocket opens an unprivileged ICMP socket. ping_group_range excludes
// every group in the sandbox, so it is refused even with NET_RAW (HR-122).
func pingSocket() error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
	if err != nil {
		return fmt.Errorf("ping socket: %w", err)
	}
	return syscall.Close(fd)
}

// icmpEcho sends an echo request to ip from a raw socket (the probe has
// NET_RAW) and waits for the reply: the network must drop it (HR-122).
func icmpEcho(ctx context.Context, ip net.IP) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return fmt.Errorf("raw ICMP socket: %w", err)
	}
	defer func() { _ = syscall.Close(fd) }()
	var id [2]byte
	_, _ = rand.Read(id[:])
	msg := append([]byte{8, 0, 0, 0, id[0], id[1], 0, 1}, "pantherclaw-probe"...)
	sum := checksum(msg)
	msg[2], msg[3] = byte(sum>>8), byte(sum)
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
		src, ok := from.(*syscall.SockaddrInet4)
		ihl := int(buf[0]&0x0f) * 4
		if ok && net.IP(src.Addr[:]).Equal(ip) && n >= ihl+8 && buf[ihl] == 0 && buf[ihl+4] == id[0] && buf[ihl+5] == id[1] {
			return nil
		}
	}
	return errors.New("no echo reply")
}

// checksum is the Internet checksum (RFC 1071).
func checksum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}
