package main

import (
	"strings"
	"time"

	"github.com/CaliDog/certstream-go"
	whois "github.com/likexian/whois-go"
	"github.com/likexian/whois-parser-go"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("example")
var susTlds = [16]string{".com", ".xyz", ".top", ".pw", ".cn", ".ru", ".io", ".tk", ".rest", ".fit", ".gq", ".work", ".ml", ".ga", ".cf", ".wang"}
var susCNs = [11]string{"c=us, st=denial, l=springfield, o=dis", "localhost", "c=xx, l=default city, o=default company ltd", "example.com", "c=au, st=some-state, o=internet widgits pty ltd", "asyncrat server", "*", "domain.com/o=my company name ltd./c=us", "orcus server", "localhost", "c=au, st=some-state, o=internet widgits pty ltd"}
var susDomain = [4]string{"paypal", "onedrive", "microsoft", "bank"}
var susIssuers = [6]string{"let's encrypt", "localhost", "example.com", "rat", "widgits", "*"}

func stream() {
	stream, errStream := certstream.CertStreamEventStream(false)
	for {
		select {
		case jq := <-stream:
			// messageType, msgTypErr := jq.String("message_type")
			issuer, issuerErr := jq.String("data", "chain", "0", "subject", "O")
			domain, domainErr := jq.String("data", "leaf_cert", "all_domains", "0")
			subjectCN, subjectCNErr := jq.String("data", "leaf_cert", "subject", "CN")

			issuer_low := strings.ToLower(issuer)
			subjectCN_low := strings.ToLower(subjectCN)
			streamData := [3]string{issuer_low, domain, subjectCN_low}

			// if msgTypErr != nil {
			// 	log.Fatal("Error decoding jq string  MsgTypErr")
			// }
			if domainErr != nil {
				log.Fatal("Error decoding jq string domainErr")
			}
			if issuerErr != nil {
				log.Fatal("Error decoding jq string on issueErr")
			}
			if subjectCNErr != nil {
				log.Fatal("Error  decoding  jq string  on  subjectCNErr")
			}

			duration := time.Duration(10) * time.Second
			time.Sleep(duration)
			log.Info(jq)
			log.Info("Analyzing...")
			analysis(streamData[0], streamData[1], streamData[2])
		case err := <-errStream:
			log.Error(err)

		}
	}
}

func analysis(issuer, domain, subjectCN string) {
	// protect := false
	// now := time.Now()
	domain = strings.TrimSpace(domain)
	domain = strings.Replace(domain, "*.", "", -1)
	domain = strings.Replace(domain, "www.", "", -1)
	log.Info("Retrieved data for ", domain)
	log.Info("Performing whois on ", domain)

	whois_raw, err := whois.Whois(domain)
	if err != nil {
		log.Info("Err @ whois command, domain value is ", domain)
		log.Fatal(err)
	}
	// if error does not equal 0. Therefor, no Error{
	//attributes to get
	//  getting  time domain  has been alive, CreatedDate - Now
	result, err := whoisparser.Parse(whois_raw)
	if err != nil {
		log.Info("Failed to parse whois for ", domain)
		log.Fatal(err)
	}
	// created_date := (result.Domain.CreatedDate)
	// registrar := (result.Registrar.Name)
	registrant_name := string(result.Registrant.Name)
	registrant_name_low := strings.ToLower(registrant_name)
	log.Info(registrant_name_low)
	if strings.Contains(registrant_name_low, "guard") {
		log.Info("It appears that the data for ", domain, " is protected...")
	}

	log.Info(result)
	for i := 0; i < len(susIssuers); i++ {
		if strings.Contains(issuer, susIssuers[i]) {
			log.Info("Issuer -> ", issuer)
			log.Info("Domain -> ", domain)
			time.Sleep(10000)
		}
	}
	log.Info("Results of ", domain, " issuer is ", issuer, " subjectCN is ", subjectCN, " Registrant is ", registrant_name_low)
}

func main() {
	stream()

}
