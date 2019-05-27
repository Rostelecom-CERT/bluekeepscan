package main

import (
	"flag"
	"github.com/Rostelecom-CERT/bluekeepscan"
	"log"
	"os"
)

func main() {
	// Create or open log file
	f, err := os.OpenFile("log.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)

	ipFilePtr := flag.String("f", "", "File with IP-address")
	pocPathPtr := flag.String("b","","Path to PoC binary https://github.com/zerosum0x0/CVE-2019-0708.git. Example:/opt/github.com/CVE-2019-0708/rdesktop-.../rdesktop")
	flag.Parse()

	app := bluekeepscan.Run(*pocPathPtr)
	app.OpenFiles(*ipFilePtr)
}
