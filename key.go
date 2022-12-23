package gossh

import (
	"bytes"
	"crypto/sha256"
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
