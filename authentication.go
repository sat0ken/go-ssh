package gossh

var stringSSHConnection = []byte(`ssh-connection`)
var methodNamePassword = []byte(`password`)

// パスワード認証だけ
func NewUserAuthenticationRequest(user, password []byte) []byte {
	return toByteArr(UserAuthenticationRequest{
		MessageCode:       []byte{SSH_MSG_USERAUTH_REQUEST},
		UsernameLength:    intTo4byte(len(user)),
		Username:          user,
		ServiceNameLength: intTo4byte(len(stringSSHConnection)),
		ServiceName:       stringSSHConnection,
		MethodNameLength:  intTo4byte(len(methodNamePassword)),
		MethodName:        methodNamePassword,
		// ChangePassowrd = False
		ChangePassword: []byte{0x00},
		PasswordLength: intTo4byte(len(password)),
		Password:       password,
	})
}

// 16の倍数までPaddingを入れる
func AddPaddingPaket(packet []byte) []byte {
	cnt := 0
	for {
		if (len(packet)+1)%16 == 0 {
			//fmt.Printf("cnt is %d\n", cnt)
			break
		}
		packet = append(packet, 0x00)
		cnt++
	}
	packet = append([]byte{byte(cnt)}, packet...)
	//packet = append(intTo4byte(len(packet)), packet...)
	return packet
}
