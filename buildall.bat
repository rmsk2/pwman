@echo off

echo Cleaning ...
go clean ./...

echo Building obfuscation helper
cd builder
go build
del ..\clitool\addr_helper.go > nul 2>&1
.\builder.exe ..\clitool\addr_helper.go
cd ..\

echo Building clitool
cd clitool
go build
del addr_helper.go > nul 2>&1
..\builder\builder.exe addr_helper.go

cd ..\pwserv
echo Building pwsrv
go build -ldflags="-H windowsgui" -o pwserv.exe

cd ..