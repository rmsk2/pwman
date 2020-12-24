package main

import "pwman/pwsrvbase"

func main() {
	p := pwsrvbase.NewSocketPwStore()
	//p.Serve(pwsrvbase.NewTCPPrepareFunc(pwsrvbase.PwServPort))
	p.Serve(pwsrvbase.NewUDSPrepareFunc(pwsrvbase.PwUDS))
}
