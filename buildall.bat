@echo off

echo Cleaning ...
go clean ./...

echo Building clitool
cd clitool
go build

cd ..\pwserv
echo Building pwsrv
go build

cd ..