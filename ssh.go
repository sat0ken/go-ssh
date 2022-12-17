package gossh

import (
	"bytes"
	"fmt"
	"golang.org/x/crypto/curve25519"
)

func ParseBinaryPacketProtocol(recv []byte) (binaryPacket []BinaryPacket) {

	for {
		if len(recv) == 0 {
			break
		} else {
			var bp BinaryPacket
			// https://tex2e.github.io/rfc-translater/html/rfc4253.html
			// 4.2. プロトコルバージョン交換
			// 末尾の2byteがCRLFだったらプロトコルバージョン交換の文字
			if bytes.Equal(recv[len(recv)-2:len(recv)], []byte{0x0d, 0x0a}) {
				bp.Payload = recv[:len(recv)-2]
				binaryPacket = append(binaryPacket, bp)
				break
			}
			// 6. Binary Packet Protocolのパケットフォーマットに従ってパースする
			bp.PacketLength = recv[0:4]
			bp.PaddingLength = recv[4:5]
			payloadLen := sumByteArr(bp.PacketLength) - 1

			bp.Payload = recv[5 : 5+payloadLen-uint(bp.PaddingLength[0])]
			bp.Padding = recv[len(recv)-int(bp.PaddingLength[0]):]
			binaryPacket = append(binaryPacket, bp)
			// パケットを縮める
			recv = recv[sumByteArr(bp.PacketLength)+4:]
		}
	}

	return binaryPacket
}

func parseNameList(payload []byte) (b []byte, length uint, name string) {
	length = sumByteArr(payload[0:4])
	nameStrLen := 4 + length
	return payload[nameStrLen:], length, fmt.Sprintf("%s", payload[4:4+nameStrLen])
}

func ParseSSHPayload(payload []byte) (msgType int, i interface{}) {
	switch payload[0] {
	case SSH_MSG_KEXINIT:
		i = readAlgorithmNegotiationPacket(payload)
		msgType = SSH_MSG_KEXINIT
	case SSH_MSG_ECDHKey_ExchangeReply:
		i = readECDHKeyExchangeReply(payload)
		msgType = SSH_MSG_ECDHKey_ExchangeReply
	case SSH_MSG_NEWKey:
		i = true
		msgType = SSH_MSG_NEWKey
	}
	return msgType, i
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

func CreateSecret(clientPriv, serverPub [32]byte) (secret [32]byte) {
	curve25519.ScalarMult(&secret, &clientPriv, &serverPub)
	fmt.Printf("client is %x, server is %x\n", clientPriv, serverPub)
	fmt.Printf("secret is %x\n", secret)
	return secret
}
