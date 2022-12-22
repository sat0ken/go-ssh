package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"gossh"
)

var inputh = "0000000a5353482d322e302d476f000000275353482d322e302d4f70656e5353485f362e37703120526173706269616e2d352b646562387531000003ab1400000000000000000000000000000000000000ac637572766532353531392d7368613235362c637572766532353531392d736861323536406c69627373682e6f72672c656364682d736861322d6e697374703235362c656364682d736861322d6e697374703338342c656364682d736861322d6e697374703532312c6469666669652d68656c6c6d616e2d67726f757031342d7368613235362c6469666669652d68656c6c6d616e2d67726f757031342d736861312c6578742d696e666f2d630000018b7273612d736861322d3531322d636572742d763031406f70656e7373682e636f6d2c7273612d736861322d3235362d636572742d763031406f70656e7373682e636f6d2c7373682d7273612d636572742d763031406f70656e7373682e636f6d2c7373682d6473732d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703235362d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703338342d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703532312d636572742d763031406f70656e7373682e636f6d2c7373682d656432353531392d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703235362c65636473612d736861322d6e697374703338342c65636473612d736861322d6e697374703532312c7273612d736861322d3531322c7273612d736861322d3235362c7373682d7273612c7373682d6473732c7373682d65643235353139000000556165733132382d67636d406f70656e7373682e636f6d2c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d637472000000556165733132382d67636d406f70656e7373682e636f6d2c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d63747200000042686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861312c686d61632d736861312d393600000042686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861312c686d61632d736861312d3936000000046e6f6e65000000046e6f6e6500000000000000000000000000000003af141eebaf49f565f8b9513ad66ab6eaf97600000096637572766532353531392d736861323536406c69627373682e6f72672c656364682d736861322d6e697374703235362c656364682d736861322d6e697374703338342c656364682d736861322d6e697374703532312c6469666669652d68656c6c6d616e2d67726f75702d65786368616e67652d7368613235362c6469666669652d68656c6c6d616e2d67726f757031342d736861310000002f7373682d7273612c7373682d6473732c65636473612d736861322d6e697374703235362c7373682d656432353531390000006c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d2c63686163686132302d706f6c7931333035406f70656e7373682e636f6d0000006c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d2c63686163686132302d706f6c7931333035406f70656e7373682e636f6d000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d73686131000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d73686131000000156e6f6e652c7a6c6962406f70656e7373682e636f6d000000156e6f6e652c7a6c6962406f70656e7373682e636f6d00000000000000000000000000000000680000001365636473612d736861322d6e69737470323536000000086e6973747032353600000041049e55bbe9a7b90353ff795b4a8733e6f24a4950c216bc855921b2e0ab46fd86a490a7b6a0d9d99f2ba7057336c1efeb2c98ed02a1049a3106e44cdd0ea1cad1ef000000202fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b7400000020bd18b1ac2411d411ca5588695eaa81255b3468bd47a78d8f2a0c1afd500f443d0000002000ee05fa00339346a56da2a7bb4460217efdf8fd36e8b9ec222feda186c3c83a"
var clientWinVersion = "5353482d322e302d476f"
var serverVersion = "5353482d322e302d4f70656e5353485f362e37703120526173706269616e2d352b6465623875310d0a"
var clientInit = "000003bc101400000000000000000000000000000000000000ac637572766532353531392d7368613235362c637572766532353531392d736861323536406c69627373682e6f72672c656364682d736861322d6e697374703235362c656364682d736861322d6e697374703338342c656364682d736861322d6e697374703532312c6469666669652d68656c6c6d616e2d67726f757031342d7368613235362c6469666669652d68656c6c6d616e2d67726f757031342d736861312c6578742d696e666f2d630000018b7273612d736861322d3531322d636572742d763031406f70656e7373682e636f6d2c7273612d736861322d3235362d636572742d763031406f70656e7373682e636f6d2c7373682d7273612d636572742d763031406f70656e7373682e636f6d2c7373682d6473732d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703235362d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703338342d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703532312d636572742d763031406f70656e7373682e636f6d2c7373682d656432353531392d636572742d763031406f70656e7373682e636f6d2c65636473612d736861322d6e697374703235362c65636473612d736861322d6e697374703338342c65636473612d736861322d6e697374703532312c7273612d736861322d3531322c7273612d736861322d3235362c7373682d7273612c7373682d6473732c7373682d65643235353139000000556165733132382d67636d406f70656e7373682e636f6d2c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d637472000000556165733132382d67636d406f70656e7373682e636f6d2c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d63747200000042686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861312c686d61632d736861312d393600000042686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861312c686d61632d736861312d3936000000046e6f6e65000000046e6f6e650000000000000000000000000000000000000000000000000000000000"
var serverinit = "000003b404141eebaf49f565f8b9513ad66ab6eaf97600000096637572766532353531392d736861323536406c69627373682e6f72672c656364682d736861322d6e697374703235362c656364682d736861322d6e697374703338342c656364682d736861322d6e697374703532312c6469666669652d68656c6c6d616e2d67726f75702d65786368616e67652d7368613235362c6469666669652d68656c6c6d616e2d67726f757031342d736861310000002f7373682d7273612c7373682d6473732c65636473612d736861322d6e697374703235362c7373682d656432353531390000006c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d2c63686163686132302d706f6c7931333035406f70656e7373682e636f6d0000006c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d2c63686163686132302d706f6c7931333035406f70656e7373682e636f6d000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d73686131000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d73686131000000156e6f6e652c7a6c6962406f70656e7373682e636f6d000000156e6f6e652c7a6c6962406f70656e7373682e636f6d0000000000000000000000000000000000"
var ecdheServerReply = "000001040a1f000000680000001365636473612d736861322d6e69737470323536000000086e6973747032353600000041049e55bbe9a7b90353ff795b4a8733e6f24a4950c216bc855921b2e0ab46fd86a490a7b6a0d9d99f2ba7057336c1efeb2c98ed02a1049a3106e44cdd0ea1cad1ef00000020bd18b1ac2411d411ca5588695eaa81255b3468bd47a78d8f2a0c1afd500f443d000000640000001365636473612d736861322d6e69737470323536000000490000002100a9a18ae8f097183678e22e10a05cbbcca05ae54cebc9ff9afaa56265b76286da000000200fd1745a6046d19541b1e329aa54aedf545120a8a7535b5a333f8c3d5042814500000000000000000000"
var clientECDHEPubKey = "2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74"
var serverECDHPubKey []byte

func main() {

	var packet []byte
	binaryPacket := gossh.ParseSSHPacket(gossh.StrtoByte(serverVersion))

	// Client Version
	packet = append(packet, gossh.IntTo4byte(len(gossh.StrtoByte(clientWinVersion)))...)
	packet = append(packet, gossh.StrtoByte(clientWinVersion)...)
	// Server Version
	packet = append(packet, gossh.IntTo4byte(len(binaryPacket[0].Payload))...)
	packet = append(packet, binaryPacket[0].Payload...)
	// Client MSG Init
	binaryPacket = gossh.ParseSSHPacket(gossh.StrtoByte(clientInit))
	fmt.Printf("Client msg init length is %d\n", len(gossh.StrtoByte(clientInit)))
	packetlen := len(gossh.StrtoByte(clientInit)) - 16 - 1 - 4
	packet = append(packet, gossh.IntTo4byte(packetlen)...)
	packet = append(packet, binaryPacket[0].Payload...)
	// Server MSG Init
	binaryPacket = gossh.ParseSSHPacket(gossh.StrtoByte(serverinit))
	packetlen = len(gossh.StrtoByte(serverinit)) - int(binaryPacket[0].PaddingLength[0]) - 1 - 4
	packet = append(packet, gossh.IntTo4byte(packetlen)...)
	packet = append(packet, binaryPacket[0].Payload...)
	// ECHDE Reply
	binaryPacket = gossh.ParseSSHPacket(gossh.StrtoByte(ecdheServerReply))
	_, i := gossh.ParseBinaryPacketPayload(binaryPacket[0].Payload)
	ecdhe := i.(gossh.ECDHEKeyExchaneReply)
	// Kex Host Key
	packetlen = len(gossh.ToByteArr(ecdhe.KEXHostKey)) - 4
	packet = append(packet, gossh.IntTo4byte(packetlen)...)
	packet = append(packet, gossh.ToByteArr(ecdhe.KEXHostKey)[4:]...)
	// Client ECDHE Public Key
	packet = append(packet, gossh.IntTo4byte(32)...)
	packet = append(packet, gossh.StrtoByte(clientECDHEPubKey)...)
	// Server ECDHE Public Key
	packet = append(packet, gossh.IntTo4byte(32)...)
	packet = append(packet, i.(gossh.ECDHEKeyExchaneReply).ECDHEServerEphemeralPublicKey...)
	serverECDHPubKey = i.(gossh.ECDHEKeyExchaneReply).ECDHEServerEphemeralPublicKey

	fmt.Printf("server public ecdhe key is %x\n", serverECDHPubKey)

	clientPrivateKey := gossh.StrtoByte("0000000000000000000000000000000000000000000000000000000000000000")

	var p [32]byte
	copy(p[:], clientPrivateKey)

	secret := gossh.CreateSecret(gossh.CopyTo32Byte(clientPrivateKey),
		gossh.CopyTo32Byte(serverECDHPubKey))
	packet = append(packet, gossh.IntTo4byte(len(secret))...)
	//packet = append(packet, []byte{0x00}...)
	packet = append(packet, secret[:]...)

	h := sha256.New()
	b := bytes.Buffer{}
	b.Write(packet)
	//b.Write(gossh.StrtoByte(inputh))

	fmt.Printf("input H is %x\n", b.Bytes())

	h.Write(b.Bytes())

	fmt.Printf("sum is %x\n", h.Sum(nil))

	fmt.Printf("A is %s\n", string([]byte{0x41}))
}
