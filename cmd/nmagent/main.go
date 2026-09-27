package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"netmonitor/internal/agent"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) > 1 && os.Args[1] == "restore" {
		fs := flag.NewFlagSet("restore", flag.ExitOnError)
		data := fs.String("data", "/var/lib/nmagent", "каталог данных")
		fs.Parse(os.Args[2:])
		if err := agent.Restore(*data); err != nil {
			log.Fatal(err)
		}
		fmt.Println("local firewall restored")
		return
	}
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		log.Fatalf("неизвестная команда %q", os.Args[1])
	}
	data := flag.String("data", "/var/lib/nmagent", "каталог данных")
	mon := flag.String("monitor", "", "хост:порт монитора")
	token := flag.String("token", "", "одноразовый токен (только первая установка)")
	enrollOnly := flag.Bool("enroll-only", false, "получить сертификат и завершиться")
	pin := flag.String("pin", "", "SHA256 ключа монитора для установки")
	flag.Parse()
	a, err := agent.Open(agent.Config{DataDir: *data, Monitor: *mon, Token: *token, Pin: *pin, ForceEnroll: *enrollOnly && *token != ""})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if *enrollOnly {
		if a.AlreadyKnown() {
			fmt.Println("kept")
			return
		}
		fmt.Println("агент ожидает подтверждения")
		return
	}
	fmt.Fprintf(os.Stderr, "nmagent %s agent_id=%s\n", agent.Version, a.ID())
	if err := a.Run(); err != nil {
		log.Fatal(err)
	}
}
