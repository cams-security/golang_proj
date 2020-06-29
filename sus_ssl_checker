package main

import (
	"strings"
	"time"

	"github.com/CaliDog/certstream-go"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("example")
var susTlds = [16]string{".com", ".xyz", ".top", ".pw", ".cn", ".ru", ".io", ".tk", ".rest", ".fit", ".gq", ".work", ".ml", ".ga", ".cf", ".wang"}
var susCNs = [11]string{"C=US, ST=Denial, L=Springfield, O=Dis", "Localhost", "C=XX, L=Default City, O=Default Company Ltd", "example.com", "C=AU, ST=Some-State, O=Internet Widgits Pty Ltd", "AsyncRAT Server", "*", "domain.com/O=My Company Name LTD./C=US", "Orcus Server", "localhost", "C=AU, ST=Some-State, O=Internet Widgits Pty Ltd"}

func stream() {
	// The false flag specifies that we want heartbeat messages.
	stream, errStream := certstream.CertStreamEventStream(false)
	for {
		select {
		case jq := <-stream:

			messageType, msgTypErr := jq.String("message_type")
			issuer, issuerErr := jq.String("data", "chain", "0", "subject", "O")
			domain, domainErr := jq.String("data", "leaf_cert", "all_domains", "0")

			if msgTypErr != nil {
				log.Fatal("Error decoding jq string")
			}
			if domainErr != nil {
				log.Fatal("Error decoding jq string")
			}
			if issuerErr != nil {
				log.Fatal("Error decoding jq string on err2")
			}

			duration := time.Duration(10) * time.Second
			time.Sleep(duration)

			if strings.Contains(issuer, "Let's Encrypt") {
				log.Info("Message type -> ", messageType)
				log.Info("Issuer -> ", issuer)
				log.Info("Domain -> ", domain)
				time.Sleep(10000)
			}
			for i := 0; i < len(susTlds); i++ {
				if strings.Contains(domain, susTlds[i]) {
					log.Info("FOUND: -> ", domain)
				}
			}
		case err := <-errStream:
			log.Error(err)

		}
	}
}

func main() {
	stream()

}
