package bluekeepscan

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const wtRDPCheck = 30 // wait time RDP check
const wtNetCheck = 5  // wait time Net check
const worker = 16

type App struct {
	ipFile string
	wg     *sync.WaitGroup
	inChan chan (string)
	pocPath string
	Counter
}

type Counter struct {
	vuln   int64
	invuln int64
	inacc  int64
	errc   int64
}

func (a *App) checkVuln(ctx context.Context, seg string) {
	cmd := exec.CommandContext(ctx, a.pocPath, seg)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		{
			log.Println(seg, err)
			a.errc++
		}
	}
	if strings.Contains(out.String(), " VULNERABLE!!!") {
		log.Println(seg, "vulnerable")
		a.vuln++
	} else if strings.Contains(out.String(), " Target appears patched.") {
		log.Println(seg, "invulnerable")
		a.invuln++
	}
}

func (a *App) checkPort() {

	var (
		ctx    context.Context
		cancel context.CancelFunc
	)
	for ip := range a.inChan {
		d := net.Dialer{Timeout: wtNetCheck * time.Second}
		seg := fmt.Sprintf("%s:%s", ip, "3389")
		_, err := d.Dial("tcp", seg)
		if err != nil {
			log.Println(seg, "inaccessible")
			a.inacc++
			continue
		}
		ctx, cancel = context.WithTimeout(context.Background(), wtRDPCheck*time.Second)
		defer cancel()
		a.checkVuln(ctx, seg)
	}
	a.wg.Done()
}

func (a *App) OpenFiles(ipfile string) {
	file, err := os.Open(ipfile)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	reader := bufio.NewReader(file)

	for i := 0; i < worker; i++ {
		a.wg.Add(1)
		go a.checkPort()
	}

	var line string
	for {
		line, err = reader.ReadString('\n')
		a.inChan <- strings.TrimSuffix(line, "\n")
		if err != nil {
			break
		}
	}
	close(a.inChan)
	if err != io.EOF {
		log.Printf(" > Failed!: %v\n", err)
	}
	a.wg.Wait()
	fmt.Printf("vuln: %d\ninvuln: %d\ninacc: %d\nerr: %d\n", a.vuln, a.invuln, a.inacc, a.errc)

}

func Run(binary string) *App {
	var wg sync.WaitGroup
	chIn := make(chan string, 1000)
	return &App{
		wg:     &wg,
		inChan: chIn,
		pocPath:binary,
	}
}
