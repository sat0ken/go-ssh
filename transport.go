package gossh

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/curve25519"
	"log"
)

const keyLength = 16
const ivLength = 12

var strInitIVCtoSisA = []byte(`A`)
var strInitIVStoCisB = []byte(`B`)
var strEnckeyCtoSisC = []byte(`C`)
var strEnckeyStoCisD = []byte(`D`)
var strIntegkeyCtoSisE = []byte(`E`)
var strIntegkeyStoCisF = []byte(`F`)

var kex_algorithms = []byte(`curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c`)
var server_host_key_algorithms_string = []byte(`rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-dss-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss,ssh-ed25519`)
var encryption_algorithms_string = []byte(`aes128-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr`)
var mac_algorithms_string = []byte(`hmac-sha2-256-etm@openssh.com,hmac-sha2-256,hmac-sha1,hmac-sha1-96`)
var compression_algorithms_string = []byte(`none`)

var clientPubKey = []byte{
	0x2f, 0xe5, 0x7d, 0xa3, 0x47, 0xcd, 0x62, 0x43,
	0x15, 0x28, 0xda, 0xac, 0x5f, 0xbb, 0x29, 0x07,
	0x30, 0xff, 0xf6, 0x84, 0xaf, 0xc4, 0xcf, 0xc2,
	0xed, 0x90, 0x99, 0x5f, 0x58, 0xcb, 0x3b, 0x74,
}

func ParseSSHPacket(recv []byte) (binaryPacket []BinaryPacket) {

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

func ParseBinaryPacketPayload(payload []byte) (msgType int, i interface{}) {
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
	case SSH_MSG_SERVICE_ACCEPT:
		i = readMessageTransport(payload)
		msgType = SSH_MSG_SERVICE_ACCEPT
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

func NewAEAD(key []byte) cipher.AEAD {
	c, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(c)
	return aead
}

func EncryptPacket(aead cipher.AEAD, packet, iv []byte) (cipherpacket []byte) {
	// パケットを暗号化
	prefix := intTo4byte(len(packet))
	fmt.Printf("EncryptPacket iv is %x, packet is %x, prefix is %x\n", iv, packet, prefix)
	cipherpacket = aead.Seal(cipherpacket, iv, packet, prefix)
	// 先頭にPacket Lengthをセット
	cipherpacket = append(prefix, cipherpacket...)

	return cipherpacket
}

func DecryptPacket(aead cipher.AEAD, cipherpacket, iv, prefix []byte) []byte {
	// パケットを復号化
	plaintext, err := aead.Open(nil, iv, cipherpacket, prefix)
	if err != nil {
		log.Fatal(err)
	}
	return plaintext
}

func createKeyorIV(K, H []byte, AtoF string, length int) []byte {
	hash := sha256.New()
	b := bytes.Buffer{}

	b.Write(K)
	b.Write(H)
	b.Write([]byte(AtoF))
	b.Write(H)
	hash.Write(b.Bytes())

	return hash.Sum(nil)[0:length]
}

// 7.2. Output from Key Exchange
func CreateEncryptionSSHKeys(K, H []byte) (enckeys EncryptionSSHKeys) {

	for i, v := range []string{`A`, `B`, `C`, `D`, `E`, `F`} {
		switch i {
		case 0:
			enckeys.InitialIvClientToServer = createKeyorIV(K, H, v, ivLength)
		case 1:
			enckeys.InitialIvServerToClient = createKeyorIV(K, H, v, ivLength)
		case 2:
			enckeys.EncryptionKeyClientToServer = createKeyorIV(K, H, v, keyLength)
		case 3:
			enckeys.EncryptionKeyServerToClient = createKeyorIV(K, H, v, keyLength)
		case 4:
			enckeys.IntegrityKeyClientToServer = createKeyorIV(K, H, v, keyLength)
		case 5:
			enckeys.IntegrityKeyServerToClient = createKeyorIV(K, H, v, keyLength)
		}
	}

	return enckeys
}

// IVをインクリメントする
func IncrementIV(iv []byte) []byte {
	length := len(iv)
	// 末尾2byteを整数にする
	src := binary.BigEndian.Uint16(iv[length-2:])
	result := make([]byte, 2)
	// +1する
	binary.BigEndian.PutUint16(result, src+1)

	// ivにセット
	iv[length-2] = result[0]
	iv[length-1] = result[1]

	return iv
}

// 10. Service Request
func NewServiceRequeest() MessageTransport {
	return MessageTransport{
		MessageCode:       []byte{SSH_MSG_SERVICE_REQUEST},
		ServiceNameLength: intTo4byte(len(ServiceRequestStringUserAuth)),
		ServiceName:       ServiceRequestStringUserAuth,
	}
}

func readMessageTransport(payload []byte) (tp MessageTransport) {
	tp.MessageCode = payload[0:1]
	tp.ServiceNameLength = payload[1:5]

	length := sumByteArr(tp.ServiceNameLength)
	tp.ServiceName = payload[5 : 5+length]
	return tp
}
