package main

import (
	"fmt"
	"log"
	"net"
)

func ConnTCP(server string, port int) net.Conn {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", server, port))
	if err != nil {
		log.Fatalf("TCP Connection error : %v\n", err)
	}
	return conn
}

func WriteTCP(conn net.Conn, data []byte) {
	buf := make([]byte, 65535)

	conn.Write(data)
	n, _ := conn.Read(buf)

	fmt.Printf("recv is %x\n", buf[:n])
}

func main() {
	s := strtoByte("1417d24906119cdea672547a11aa150582000000e6637572766532353531392d7368613235362c637572766532353531392d736861323536406c69627373682e6f72672c656364682d736861322d6e697374703235362c656364682d736861322d6e697374703338342c656364682d736861322d6e697374703532312c6469666669652d68656c6c6d616e2d67726f75702d65786368616e67652d7368613235362c6469666669652d68656c6c6d616e2d67726f757031362d7368613531322c6469666669652d68656c6c6d616e2d67726f757031382d7368613531322c6469666669652d68656c6c6d616e2d67726f757031342d736861323536000000417273612d736861322d3531322c7273612d736861322d3235362c7373682d7273612c65636473612d736861322d6e697374703235362c7373682d656432353531390000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d0000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d73686131000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d73686131000000156e6f6e652c7a6c6962406f70656e7373682e636f6d000000156e6f6e652c7a6c6962406f70656e7373682e636f6d0000000000000000000000000000000000000000000000")

	//conn := ConnTCP("192.168.0.15", 22)
	//clientSSHString = append(clientSSHString, []byte{0x0d, 0x0a}...)
	//
	////fmt.Printf("%x\n", clientSSHString)
	//WriteTCP(conn, clientSSHString)
	//ParseSSHPacket(strtoByte("5353482d322e302d4f70656e5353485f362e37703120526173706269616e2d352b6465623875310d0a"))
	anp := ParseAlgorithmNegotiationPacket(s)
	printPacket(anp)
}
