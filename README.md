# BlueKeepScan

Simple wrapper over PoC from [@zerosum0x0](https://twitter.com/zerosum0x0) for checking CVE-2019-0708 in large network in multithreading.


### Prepare

First of all you shouldn download and install original: 

```

git clone https://github.com/zerosum0x0/CVE-2019-0708.git
cd CVE-2019-0708/rdesktop-fork-bd6aa6acddf0ba640a49834807872f4cc0d0a773/
./bootstrap
./configure --disable-credssp --disable-smartcard
make
```

We *strongly* recommend to read original README from [original](https://github.com/zerosum0x0/CVE-2019-0708)

Then scan you network and find open 3389/tcp ports and pull the found addresses to file.
You can use masscan/nmap/etc for this purpose.

### Running

```
go get -v github.com/Rostelecom-CERT/bluekeepscan
cd $GOPATH/github.com/Rostelecom-CERT/bluekeepscan/cmd/bluekeepscan/main
go run main.go -f FILE_WITH_IP -b PATH_TO_RDESKTOP

```

If you don't have go, you can start binary file

```
./bluekeepscan -f FILE_WITH_IP -b PATH_TO_RDESKTOP
```

bluekeepscan create file log.log with results.