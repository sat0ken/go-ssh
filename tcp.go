package gossh

import (
	"fmt"
	"log"
	"net"
)

func ConnTCP(server string, port int) net.Conn {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", server, port))
	if err != nil {
		log.Fatalf("TCP Connection error : %v\n", err)
	}
	return conn
}

func WriteTCP(conn net.Conn, data []byte) []byte {
	buf := make([]byte, 65535)

	conn.Write(data)
	n, _ := conn.Read(buf)

	return buf[:n]
}
