package main

import (
	"fmt"
	"gossh"
)

func main() {
	server := "192.168.0.15"
	port := 22
	// SSHサーバにTCP接続
	conn := gossh.ConnTCP(server, port)

	client := gossh.ClientSSHVersionString
	// 改行コードを追加
	client = append(client, []byte{0x0d, 0x0a}...)

	// ClientのSSHバージョンを送信
	recv := gossh.WriteTCP(conn, client)
	// 受信したパケットを読み込む
	packet := gossh.ParseSSHPacket(recv)

	fmt.Printf("Server Protocol Version is %s\n", packet[0].Payload)

	// ClientからSSH_MSG_INITを送信
	recv = gossh.WriteTCP(conn, gossh.NewClientKeyExchangeInit())
	packet = gossh.ParseSSHPacket(recv)

	// recvしたパケットをパース
	_, msgInit := gossh.ParseBinaryPacketPayload(packet[0].Payload)
	fmt.Printf("Server SSH_MSG_INIT is %+v\n", msgInit.(gossh.AlgorithmNegotiationPacket))

}
