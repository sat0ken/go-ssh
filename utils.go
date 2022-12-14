package gossh

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"reflect"
)

func sumByteArr(arr []byte) uint {
	var sum uint
	for i := 0; i < len(arr); i++ {
		if i%2 == 0 {
			sum += uint(binary.BigEndian.Uint16(arr[i:]))
		}
	}
	return sum
}

func strtoByte(str string) []byte {
	return StrtoByte(str)
}

func StrtoByte(str string) []byte {
	b, err := hex.DecodeString(str)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func intTo4byte(i int) []byte {
	return IntTo4byte(i)
}

func IntTo4byte(i int) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32((i)))
	return b
}

func printPacket(value interface{}) {
	rv := reflect.ValueOf(value)
	rt := rv.Type()

	for i := 0; i < rv.NumField(); i++ {
		field := rt.Field(i)

		switch rv.Field(i).Interface().(type) {
		case uint:
			fmt.Printf("%s is %d\n", field.Name, rv.Field(i).Interface().(uint))
		case []uint8:
			fmt.Printf("%s is %x\n", field.Name, rv.Field(i).Interface().([]uint8))
		case string:
			fmt.Printf("%s is %s\n", field.Name, rv.Field(i).Interface().(string))
		}
	}
}

func toByteArr(value interface{}) []byte {
	return ToByteArr(value)
}

// ToByteArr 各構造体のフィールドが持つbyteをflatな配列にする
func ToByteArr(value interface{}) []byte {
	rv := reflect.ValueOf(value)
	//rt := rv.Type()
	var arr []byte

	for i := 0; i < rv.NumField(); i++ {
		b := rv.Field(i).Interface().([]byte)
		arr = append(arr, b...)
	}

	return arr
}

func noRandomByte(length int) []byte {
	b := make([]byte, length)
	for i := 0; i < length; i++ {
		b[i] = 0x00
	}
	return b
}

func CopyTo32Byte(src []byte) (dst [32]byte) {
	copy(dst[:], src)
	return dst
}

func WriteBuffer(b bytes.Buffer, packet []byte) bytes.Buffer {
	b.Write(intTo4byte(len(packet)))
	b.Write(packet)
	return b
}
