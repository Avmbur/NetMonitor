package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"netmonitor/internal/server"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "init":
		fs := flag.NewFlagSet("init", flag.ExitOnError)
		data := fs.String("data", "/var/lib/nmserver", "каталог данных")
		pass := fs.String("password", "", "пароль adm")
		passStdin := fs.Bool("password-stdin", false, "прочитать пароль из stdin")
		host := fs.String("listen-host", "0.0.0.0", "хост в команде агента и bind")
		port := fs.Int("listen-port", 8443, "порт приёмника")
		_ = fs.Parse(os.Args[2:])
		if *passStdin {
			line, err := bufio.NewReader(os.Stdin).ReadString('\n')
			if err != nil {
				log.Fatal("не удалось прочитать пароль")
			}
			*pass = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		}
		if err := server.Init(server.Config{DataDir: *data, ListenHost: *host, ListenPort: *port}, *pass); err != nil {
			log.Fatal(err)
		}
		fmt.Println("nmserver init: ok")
	case "token":
		fs := flag.NewFlagSet("token", flag.ExitOnError)
		data := fs.String("data", "/var/lib/nmserver", "каталог данных")
		_ = fs.Parse(os.Args[2:])
		tok, err := server.NewToken(*data)
		if err != nil {
			log.Fatal(err)
		}
		cmd, err := server.InstallCommand(*data, tok)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(cmd)
	case "endpoint":
		fs := flag.NewFlagSet("endpoint", flag.ExitOnError)
		data := fs.String("data", "/var/lib/nmserver", "каталог данных")
		_ = fs.Parse(os.Args[2:])
		ep, err := server.Endpoint(*data)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(ep)
	case "trust":
		fs := flag.NewFlagSet("trust", flag.ExitOnError)
		data := fs.String("data", "/var/lib/nmserver", "каталог данных")
		host := fs.String("hostname", "", "имя агента, пусто — все pending")
		_ = fs.Parse(os.Args[2:])
		n, err := server.TrustPending(*data, *host)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("trusted %d\n", n)
	case "block":
		fs := flag.NewFlagSet("block", flag.ExitOnError)
		data := fs.String("data", "/var/lib/nmserver", "каталог данных")
		ip := fs.String("ip", "", "адрес")
		ttl := fs.String("ttl", "1h", "срок")
		_ = fs.Parse(os.Args[2:])
		id, err := server.BlockIP(*data, *ip, server.ParseTTL(*ttl), true)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(id)
	case "unblock":
		fs := flag.NewFlagSet("unblock", flag.ExitOnError)
		data := fs.String("data", "/var/lib/nmserver", "каталог данных")
		ip := fs.String("ip", "", "адрес")
		_ = fs.Parse(os.Args[2:])
		if err := server.UnblockIP(*data, *ip); err != nil {
			log.Fatal(err)
		}
		fmt.Println("ok")
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		data := fs.String("data", "/var/lib/nmserver", "каталог данных")
		host := fs.String("listen-host", "", "переопределить bind host")
		port := fs.Int("listen-port", 0, "переопределить порт")
		_ = fs.Parse(os.Args[2:])
		cfg := server.Config{DataDir: *data, ListenHost: *host, ListenPort: *port, ArtifactDir: os.Getenv("NM_ARTIFACT_DIR")}
		s, err := server.Listen(cfg)
		if err != nil {
			log.Fatal(err)
		}
		if err := s.Serve(); err != nil {
			log.Fatal(err)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `nmserver — монитор netmonitor

  nmserver init    --data DIR --password PASS [--listen-host HOST] [--listen-port 8443]
  nmserver token   --data DIR
  nmserver endpoint --data DIR
  nmserver trust   --data DIR [--hostname NAME]
  nmserver block   --data DIR --ip ADDR [--ttl 1h]
  nmserver unblock --data DIR --ip ADDR
  nmserver run     --data DIR

Заводской порт 8443. Если занят — не стартуем.
`)
}
