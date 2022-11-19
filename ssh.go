package main

import (
	"bytes"
	"fmt"
)

const (
	SSH_MSG_DISCONNECT      = 1
	SSH_MSG_IGNORE          = 2
	SSH_MSG_UNIMPLEMENTED   = 3
	SSH_MSG_DEBUG           = 4
	SSH_MSG_SERVICE_REQUEST = 5
	SSH_MSG_SERVICE_ACCEPT  = 6
	SSH_MSG_KEXINIT         = 20
)

var clientSSHString = []byte(`SSH-2.0-OpenSSH_8.9p1 Ubuntu-3`)

/*
https://tex2e.github.io/rfc-translater/html/rfc4253.html
6. Binary Packet Protocol
Each packet is in the following format:

各パケットは次の形式です。

	uint32    packet_length
	byte      padding_length
	byte[n1]  payload; n1 = packet_length - padding_length - 1
	byte[n2]  random padding; n2 = padding_length
	byte[m]   mac (Message Authentication Code - MAC); m = mac_length
*/
type BinaryPacket struct {
	PacketLength  []byte
	PaddingLength []byte
	Payload       []byte
	Padding       []byte
}

/*
RFC4253
7.1.  Algorithm Negotiation

	Key exchange begins by each side sending the following packet:

	   byte         SSH_MSG_KEXINIT
	   byte[16]     cookie (random bytes)
	   name-list    kex_algorithms
	   name-list    server_host_key_algorithms
	   name-list    encryption_algorithms_client_to_server
	   name-list    encryption_algorithms_server_to_client
	   name-list    mac_algorithms_client_to_server
	   name-list    mac_algorithms_server_to_client
	   name-list    compression_algorithms_client_to_server
	   name-list    compression_algorithms_server_to_client
	   name-list    languages_client_to_server
	   name-list    languages_server_to_client
	   boolean      first_kex_packet_follows
	   uint32       0 (reserved for future extension)
*/
type AlgorithmNegotiationPacket struct {
	SSHMsgType                                []byte
	Cookie                                    []byte
	KeyAlgorithmsLength                       uint
	KeyAlgorithms                             string
	ServerHostKeyAlgorithmsLength             uint
	ServerHostKeyAlgorithms                   string
	EncryptionAlgorithmsClientToServerLength  uint
	EncryptionAlgorithmsClientToServer        string
	EncryptionAlgorithmsServerToClientLength  uint
	EncryptionAlgorithmsServerToClient        string
	MacAlgorithmsClientToServerLength         uint
	MacAlgorithmsClientToServer               string
	MacAlgorithmsServerToClientLength         uint
	MacAlgorithmsServerToClient               string
	CompressionAlgorithmsClientToServerLength uint
	CompressionAlgorithmsClientToServer       string
	CompressionAlgorithmsServerToClientLength uint
	CompressionAlgorithmsServerToClient       string
	LanguageClientToServerLength              uint
	LanguageClientToServer                    []byte
	LanguageServerToClientLength              uint
	LanguageServerToClient                    []byte
	FirstKEXPacketFollows                     []byte
	Reserved                                  []byte
}

func ParseSSHPacket(recv []byte) {
	// https://tex2e.github.io/rfc-translater/html/rfc4253.html
	// 4.2. プロトコルバージョン交換
	// 末尾の2byteがCRLFだったらプロトコルバージョン交換の文字
	if bytes.Equal(recv[len(recv)-2:len(recv)], []byte{0x0d, 0x0a}) {
		fmt.Printf("Protocol Version Exchange : %s\n", recv[:len(recv)-2])
	}

	ParseBinaryPacketProtocol(recv)
}

func ParseBinaryPacketProtocol(recv []byte) BinaryPacket {
	// 6. Binary Packet Protocolのパケットフォーマットに従ってパースする
	var ssh BinaryPacket
	ssh.PacketLength = recv[0:4]
	ssh.PaddingLength = recv[4:5]
	payloadLen := sumByteArr(ssh.PacketLength) - 1

	ssh.Payload = recv[5 : 5+payloadLen]
	ssh.Padding = recv[len(recv)-int(ssh.PaddingLength[0]):]
	return ssh
}

func parseNameList(payload []byte) (b []byte, length uint, name string) {
	length = sumByteArr(payload[0:4])
	nameStrLen := 4 + length
	return payload[nameStrLen:], length, fmt.Sprintf("%s", payload[4:4+nameStrLen])
}

func ParseAlgorithmNegotiationPacket(payload []byte) AlgorithmNegotiationPacket {
	var anp AlgorithmNegotiationPacket
	anp.SSHMsgType = payload[0:1]
	anp.Cookie = payload[1:17]

	// KeyAlgorithmsをセット
	payload, anp.KeyAlgorithmsLength, anp.KeyAlgorithms = parseNameList(payload[17:])
	// ServerHostKeyAlgorithmsをセット
	payload, anp.ServerHostKeyAlgorithmsLength,
		anp.ServerHostKeyAlgorithms = parseNameList(payload[:])
	// 	EncryptionAlgorithmsClientToServerをセット
	payload, anp.EncryptionAlgorithmsClientToServerLength,
		anp.EncryptionAlgorithmsClientToServer = parseNameList(payload[:])
	// EncryptionAlgorithmsServerToClientをセット
	payload, anp.EncryptionAlgorithmsServerToClientLength,
		anp.EncryptionAlgorithmsServerToClient = parseNameList(payload[:])
	// MacAlgorithmsClientToServerをセット
	payload, anp.MacAlgorithmsClientToServerLength,
		anp.MacAlgorithmsClientToServer = parseNameList(payload[:])
	// MacAlgorithmsServerToClientをセット
	payload, anp.MacAlgorithmsServerToClientLength,
		anp.MacAlgorithmsServerToClient = parseNameList(payload[:])
	// CompressionAlgoeithmsClientToServerをセット
	payload, anp.CompressionAlgorithmsClientToServerLength,
		anp.CompressionAlgorithmsClientToServer = parseNameList(payload[:])
	// CompressionAlgorithmsServerToclientをセット
	payload, anp.CompressionAlgorithmsServerToClientLength,
		anp.CompressionAlgorithmsServerToClient = parseNameList(payload[:])

	// LanguagesClientToServerをセット
	anp.LanguageClientToServerLength = sumByteArr(payload[0:4])
	if anp.LanguageClientToServerLength == 0 {
		payload = payload[4:]
		anp.LanguageClientToServerLength = sumByteArr(payload[0:4])
	}
	// パケットを詰める
	payload = payload[4:]
	anp.FirstKEXPacketFollows = payload[0:1]
	anp.Reserved = payload[1:5]
	return anp
}

func NewClientKeyExchangeInit() []byte {
	keyExchange := []byte{SSH_MSG_KEXINIT}
	keyExchange = append(keyExchange, toByteArr(NewAlgorithmsNegotiation())...)

	init := BinaryPacket{
		PacketLength:  intTo4byte(len(keyExchange) + 1 + 16),
		PaddingLength: []byte{0x10}, // Padding = 16
		Payload:       keyExchange,
		Padding: []byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}

	return toByteArr(init)
}
