echo Cleaning ...
go clean ./...

echo Building clitool
cd clitool
go build 

echo Building pwserv
cd ../pwserv
go build