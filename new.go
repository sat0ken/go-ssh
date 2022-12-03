package main

import "golang.org/x/crypto/curve25519"

func NewClientKeyExchangeInit() []byte {
	keyExchange := []byte{SSH_MSG_KEXINIT}
	keyExchange = append(keyExchange, toByteArr(NewClientAlgorithmsNegotiation())...)

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

func NewClientAlgorithmsNegotiation() AlgorithmNegotiation {
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

func NewClientECDHEKeyExchangeInit() []byte {
	ecdheKeyExInit := []byte{SSH_MSG_ECDHKey_ExchangeInit}
	ecdheKeyExInit = append(ecdheKeyExInit, intTo4byte(curve25519.ScalarSize)...)
	ecdheKeyExInit = append(ecdheKeyExInit, clientPubKey...)

	return toByteArr(BinaryPacket{
		PacketLength:  intTo4byte(len(ecdheKeyExInit) + 1 + 6),
		PaddingLength: []byte{0x06},
		Payload:       ecdheKeyExInit,
		Padding:       noRandomByte(6),
	})
}
