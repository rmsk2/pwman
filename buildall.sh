echo Cleaning ...
go clean ./...

echo Building obfuscation helper
cd builder
go build
rm ../clitool/addr_helper.go
./builder ../clitool/addr_helper.go
cd ../

echo Building clitool
cd clitool
go build 

echo Building pwserv
cd ../pwserv
go build