//go:build windows
// +build windows

package main

import (
	"pwman/fcrypt"
	"pwman/pwsrvbase"
	"pwman/pwsrvbase/windomainsock"
)

// NewContext creates a new command context
func NewContext() *CmdContext {
	return &CmdContext{
		//client: pwsrvbase.NewGenericJSONClient(pwsrvbase.NewSocketTransactor(pwsrvbase.PwServPort)),
		client:      pwsrvbase.NewGenericJSONClient(windomainsock.NewUDSTransactor()),
		jotsManager: fcrypt.GetGjotsManager(),
	}
}
