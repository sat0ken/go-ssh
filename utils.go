package main

import (
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
	//fmt.Printf("0x%x : %b\n", sum, sum)
	return sum
}

func strtoByte(str string) []byte {
	b, err := hex.DecodeString(str)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func intTo4byte(i int) []byte {
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

// 各構造体のフィールドが持つbyteをflatな配列にする
func toByteArr(value interface{}) []byte {
	rv := reflect.ValueOf(value)
	//rt := rv.Type()
	var arr []byte

	for i := 0; i < rv.NumField(); i++ {
		b := rv.Field(i).Interface().([]byte)
		arr = append(arr, b...)
	}

	return arr
}
