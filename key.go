package main

var kex_algorithms = []byte(`curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c`)
var server_host_key_algorithms_string = []byte(`rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-dss-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss,ssh-ed25519`)
var encryption_algorithms_string = []byte(`aes128-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr`)
var mac_algorithms_string = []byte(`hmac-sha2-256-etm@openssh.com,hmac-sha2-256,hmac-sha1,hmac-sha1-96`)
var compression_algorithms_string = []byte(`none`)

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

func NewAlgorithmsNegotiation() AlgorithmNegotiation {
	algo := AlgorithmNegotiation{
		Cookie:                                    strtoByte("359e11884e898b0bdb2ad48ab1cc799a"),
		KexAlgorithmsLength:                       intTo4byte(len(kex_algorithms)),
		KexAlgorithmsString:                       kex_algorithms,
		ServerHostKeyAlgorithmsLength:             intTo4byte(len(server_host_key_algorithms_string)),
		ServerHostKeyAlgorithmsString:             server_host_key_algorithms_string,
		EncryptionAlgorithmsClientToServerLength:  intTo4byte(len(encryption_algorithms_string)),
		EncryptionAlgorithmsClientToServerString:  encryption_algorithms_string,
		EncryptionAlgorithmsServerToClientLength:  intTo4byte(len(encryption_algorithms_string)),
		EncryptionAlgorithmsServerToClientString:  encryption_algorithms_string,
		MacAlgorithmsClientToServerLength:         intTo4byte(len(mac_algorithms_string)),
		MacAlgorithmsClientToServerString:         mac_algorithms_string,
		MacAlgorithmsServerToClientLength:         intTo4byte(len(mac_algorithms_string)),
		MacAlgorithmsServerToClientString:         mac_algorithms_string,
		CompressionAlgorithmsClientToServerLength: intTo4byte(len(compression_algorithms_string)),
		CompressionAlgorithmsClientToServerString: compression_algorithms_string,
		CompressionAlgorithmsServerToClientLength: intTo4byte(len(compression_algorithms_string)),
		CompressionAlgorithmsServerToClientString: compression_algorithms_string,
		LanguagesClientToServerLength:             intTo4byte(0),
		LanguagesServerToClientLength:             intTo4byte(0),
		FirstKEXPacketFollows:                     []byte{0x00},
		Reserved:                                  intTo4byte(0),
	}

	return algo
}
