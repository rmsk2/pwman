package main

import "pwman/pwsrvbase"

func main() {
	p := pwsrvbase.NewPwStore()
	p.Serve(pwsrvbase.PwServPort)
}
