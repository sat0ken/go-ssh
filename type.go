package gossh

const (
	SSH_MSG_DISCONNECT            = 1
	SSH_MSG_IGNORE                = 2
	SSH_MSG_UNIMPLEMENTED         = 3
	SSH_MSG_DEBUG                 = 4
	SSH_MSG_SERVICE_REQUEST       = 5
	SSH_MSG_SERVICE_ACCEPT        = 6
	SSH_MSG_KEXINIT               = 20
	SSH_MSG_NEWKey                = 21
	SSH_MSG_ECDHKey_ExchangeInit  = 30
	SSH_MSG_ECDHKey_ExchangeReply = 31
)

var clientSSHVersionString = []byte(`SSH-2.0-OpenSSH_8.9p1 Ubuntu-3`)

type SSHPacket struct {
	RawPacket      []byte
	SequenceNumber int
	BinaryPacket
}

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

// 7.1. Algorithm Negotiation
type AlgorithmNegotiation struct {
	Cookie                                    []byte
	KexAlgorithmsLength                       []byte
	KexAlgorithmsString                       []byte
	ServerHostKeyAlgorithmsLength             []byte
	ServerHostKeyAlgorithmsString             []byte
	EncryptionAlgorithmsClientToServerLength  []byte
	EncryptionAlgorithmsClientToServerString  []byte
	EncryptionAlgorithmsServerToClientLength  []byte
	EncryptionAlgorithmsServerToClientString  []byte
	MacAlgorithmsClientToServerLength         []byte
	MacAlgorithmsClientToServerString         []byte
	MacAlgorithmsServerToClientLength         []byte
	MacAlgorithmsServerToClientString         []byte
	CompressionAlgorithmsClientToServerLength []byte
	CompressionAlgorithmsClientToServerString []byte
	CompressionAlgorithmsServerToClientLength []byte
	CompressionAlgorithmsServerToClientString []byte
	LanguagesClientToServerLength             []byte
	LanguagesClientToServerString             []byte
	LanguagesServerToClientLength             []byte
	LanguagesServerToClientString             []byte
	FirstKEXPacketFollows                     []byte
	Reserved                                  []byte
}

type ECDHEKeyExchaneReply struct {
	SSHMsgType []byte
	KEXHostKey struct {
		HostKeyLength              []byte
		HostKeyTypeLength          []byte
		HostKeyType                []byte
		ECDSACurveIdentifierLength []byte
		ECDSACurveIdentifier       []byte
		ECDSAPublicKeyLength       []byte
		ECDSAPublicKey             []byte
	}
	ECDHEServerEphemeralPublicKeyLength []byte
	ECDHEServerEphemeralPublicKey       []byte
	KEXHostSignature                    struct {
		HostSignatureLength     []byte
		HostSignatureTypeLength []byte
		HostSignatureType       []byte
		HostSignature           []byte
	}
}
