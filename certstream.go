package main

import (
	"time"

	"github.com/CaliDog/certstream-go"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("example")
var susTlds = [15]string{".xyz", ".top", ".pw", ".cn", ".ru", ".io", ".tk", ".rest", ".fit", ".gq", ".work", ".ml", ".ga", ".cf", ".wang"}
var susCNs = [11]string{"C=US, ST=Denial, L=Springfield, O=Dis", "Localhost", "C=XX, L=Default City, O=Default Company Ltd", "example.com", "C=AU, ST=Some-State, O=Internet Widgits Pty Ltd", "AsyncRAT Server", "*", "domain.com/O=My Company Name LTD./C=US", "Orcus Server", "localhost", "C=AU, ST=Some-State, O=Internet Widgits Pty Ltd"}

// type cert struct  {
//   cert [] cert 'json:"cert"'
//
// }
func stream() {
	// The false flag specifies that we want heartbeat messages.
	stream, errStream := certstream.CertStreamEventStream(false)
	for {
		select {
		case jq := <-stream:
			messageType, err := jq.String("message_type")
			// sleep(10000)
			// test, err := jq.String("data")
			if err != nil {
				log.Fatal("Error decoding jq string")
			}
			// log.Info("recv: ", jq)
			// cert = log.Info("recv: ", jq)
			duration := time.Duration(10) * time.Second
			time.Sleep(duration)
			log.Info("Message type -> ", messageType)
			// log.Info(jq.String("data", "leaf_cert", "subject", "CN"))
			issuer, test := jq.String("data", "chain", "extensions", "authorityInfoAccess")
			log.Info("Issuer -> ", issuer, test)
			// log.Info("Data -> ", test)
			time.Sleep(10000)
		case err := <-errStream:
			log.Error(err)
		}
	}
}

// func analysis() {
// 	cert = cert
// 	print(cert)
// 	time.Sleep(10000)
//
// }

func main() {
	stream()

}
