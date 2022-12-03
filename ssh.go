package main

import (
	"bytes"
	"fmt"
)

func ParseBinaryPacketProtocol(recv []byte) interface{} {

	// https://tex2e.github.io/rfc-translater/html/rfc4253.html
	// 4.2. プロトコルバージョン交換
	// 末尾の2byteがCRLFだったらプロトコルバージョン交換の文字
	if bytes.Equal(recv[len(recv)-2:len(recv)], []byte{0x0d, 0x0a}) {
		return fmt.Sprintf("Protocol Version Exchange : %s\n", recv[:len(recv)-2])
	}

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

func ParseSSHPayload(payload []byte) interface{} {
	var i interface{}
	switch payload[0] {
	case SSH_MSG_KEXINIT:
		i = readAlgorithmNegotiationPacket(payload)
	case SSH_MSG_ECDHKey_ExchangeReply:
		i = readECDHKeyExchangeReply(payload)
	}
	return i
}

func readAlgorithmNegotiationPacket(payload []byte) AlgorithmNegotiationPacket {
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

func readECDHKeyExchangeReply(payload []byte) (ecdhkey ECDHEKeyExchaneReply) {
	var length uint
	ecdhkey.SSHMsgType = payload[0:1]
	ecdhkey.KEXHostKey.HostKeyLength = payload[1:5]
	ecdhkey.KEXHostKey.HostKeyTypeLength = payload[5:9]

	length = sumByteArr(ecdhkey.KEXHostKey.HostKeyTypeLength)
	ecdhkey.KEXHostKey.HostKeyType = payload[9 : 9+length]
	// パケットを縮める
	payload = payload[9+length:]
	ecdhkey.KEXHostKey.ECDSACurveIdentifierLength = payload[0:4]
	length = sumByteArr(
		ecdhkey.KEXHostKey.ECDSACurveIdentifierLength)
	ecdhkey.KEXHostKey.ECDSACurveIdentifier = payload[4 : 4+length]
	// パケットを縮める
	payload = payload[4+length:]
	ecdhkey.KEXHostKey.ECDSAPublicKeyLength = payload[0:4]
	length = sumByteArr(
		ecdhkey.KEXHostKey.ECDSAPublicKeyLength)
	ecdhkey.KEXHostKey.ECDSAPublicKey = payload[4 : 4+length]
	// パケットを縮める
	payload = payload[4+length:]
	ecdhkey.ECDHEServerEphemeralPublicKeyLength = payload[0:4]
	length = sumByteArr(ecdhkey.ECDHEServerEphemeralPublicKeyLength)
	ecdhkey.ECDHEServerEphemeralPublicKey = payload[4 : 4+length]
	// パケットを縮める
	payload = payload[4+length:]
	ecdhkey.KEXHostSignature.HostSignatureLength = payload[0:4]
	ecdhkey.KEXHostSignature.HostSignatureTypeLength = payload[4:8]
	length = sumByteArr(
		ecdhkey.KEXHostSignature.HostSignatureTypeLength)
	ecdhkey.KEXHostSignature.HostSignatureType = payload[8 : 8+length]
	// パケットを縮める
	payload = payload[8+length:]
	remainlen := sumByteArr(
		ecdhkey.KEXHostSignature.HostSignatureLength)
	remainlen -= uint(len(ecdhkey.KEXHostSignature.HostSignatureTypeLength))
	remainlen -= uint(len(ecdhkey.KEXHostSignature.HostSignatureType))

	ecdhkey.KEXHostSignature.HostSignature = payload[:remainlen]

	return ecdhkey
}
