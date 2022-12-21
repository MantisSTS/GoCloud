package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/projectdiscovery/mapcidr"
)

type DNSLookup struct {
	DomainName string
	Nameserver string
	IPAddr     []string
}

type ProgArgs struct {
	DomainFile string
	NSFile     string
	OutputFile string
}

func (dns *DNSLookup) DoLookup() (*DNSLookup, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(10000),
			}
			return d.DialContext(ctx, network, fmt.Sprintf("%s:53", dns.Nameserver))
		},
	}

	var err error
	dns.IPAddr, err = r.LookupHost(context.Background(), dns.DomainName)

	return dns, err
}

type CloudServices struct {
	CloudServices []CloudService
}

type CloudService struct {
	Name    string
	IPRange []string
}

func (c *CloudServices) IsCloud(ip string) bool {
	for _, service := range c.CloudServices {
		for _, rangeIP := range service.IPRange {
			if rangeIP == ip {
				return true
			}
		}
	}
	return false
}

func (c *CloudServices) UpdateCloudServices() {
	// Fetch the Cloud Services IP Ranges

	localFile := "ip-ranges.json"

	// create local file for writing
	file, err := os.Create(localFile)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	urls := make(map[string]string)
	urls["AWS"] = "https://ip-ranges.amazonaws.com/ip-ranges.json"
	urls["Cloudflare"] = "https://www.cloudflare.com/ips-v4"
	urls["Cloudflare6"] = "https://www.cloudflare.com/ips-v6"
	urls["Azure"] = "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20221212.json"

	var wg sync.WaitGroup
	// Parse the JSON
	for name, url := range urls {
		wg.Add(1)

		go func(name string, url string) {
			defer wg.Done()

			res, err := http.Get(url)
			fmt.Println("[+] Fetching IP ranges for", name)
			if err != nil {
				panic(err)
			}

			switch name {
			case "AWS":
				type AWSIPRanges struct {
					SyncToken  string `json:"syncToken"`
					CreateDate string `json:"createDate"`
					Prefixes   []struct {
						IPPrefix string `json:"ip_prefix"`
						Region   string `json:"region"`
						Service  string `json:"service"`
					} `json:"prefixes"`
					Ipv6Prefixes []struct {
						IPPrefix string `json:"ipv6_prefix"`
						Region   string `json:"region"`
						Service  string `json:"service"`
					} `json:"ipv6_prefixes"`
				}

				var aws AWSIPRanges
				err = json.NewDecoder(res.Body).Decode(&aws)
				if err != nil {
					panic(err)
				}

				for _, prefix := range aws.Prefixes {
					ips, err := mapcidr.IPAddresses(prefix.IPPrefix)

					if err != nil {
						panic(err)
					}

					c.CloudServices = append(c.CloudServices, CloudService{Name: name, IPRange: ips})
				}

			case "Cloudflare":
			case "Cloudflare6":
				scanner := bufio.NewScanner(res.Body)
				scanner.Split(bufio.ScanLines)
				for scanner.Scan() {
					ips, err := mapcidr.IPAddresses(scanner.Text())
					if err != nil {
						panic(err)
					}
					c.CloudServices = append(c.CloudServices, CloudService{Name: name, IPRange: ips})
				}
			case "Azure":

				type AzureIPRanges struct {
					Values []struct {
						Name       string `json:"name"`
						ID         string `json:"id"`
						Location   string `json:"location"`
						Properties struct {
							AddressPrefixes []string `json:"addressPrefixes"`
							Platform        string   `json:"platform"`
						} `json:"properties"`
					} `json:"values"`
				}

				var azure AzureIPRanges
				err = json.NewDecoder(res.Body).Decode(&azure)
				if err != nil {
					panic(err)
				}

				for _, prefix := range azure.Values {
					for _, ip := range prefix.Properties.AddressPrefixes {
						ips, err := mapcidr.IPAddresses(ip)

						if err != nil {
							panic(err)
						}
						c.CloudServices = append(c.CloudServices, CloudService{Name: name, IPRange: ips})
					}
				}
			}
		}(name, url)
	}
	wg.Wait()

	// Write the results to the file in JSON format
	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	err = enc.Encode(c)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%+v\n", c.CloudServices)

}

func init() {
	cloud := CloudServices{}
	fmt.Println("[+] Fetching latest IP ranges for the cloud services")
	cloud.UpdateCloudServices()
}

func main() {

	args := ProgArgs{}

	// Create a flag to read the domain name from a file or from the command line
	flag.StringVar(&args.DomainFile, "df", "", "File containing domains to lookup")
	flag.StringVar(&args.NSFile, "nf", "nameservers.txt", "File containing nameservers to use for lookup")
	flag.StringVar(&args.OutputFile, "o", "", "Output File (JSON)")
	flag.Parse()

	cloud := CloudServices{}
	cloud.UpdateCloudServices()
	// resultsChan := make(chan DNSLookup, 100)
	// Read the nameservers from the file
	nameserverFile, err := os.Open(args.NSFile)
	if err != nil {
		panic(err)
	}

	nsScanner := bufio.NewScanner(nameserverFile)
	nsScanner.Split(bufio.ScanLines)
	var nameservers []string
	for nsScanner.Scan() {
		nameservers = append(nameservers, nsScanner.Text())
	}
	nameserverFile.Close()

	// Read the domain names from the file
	domainFile, err := os.Open(args.DomainFile)
	if err != nil {
		panic(err)
	}

	dfScanner := bufio.NewScanner(domainFile)
	dfScanner.Split(bufio.ScanLines)
	for dfScanner.Scan() {
		d := DNSLookup{}
		d.DomainName = dfScanner.Text()
		d.Nameserver = nameservers[rand.Intn(len(nameservers))]

		res, err := d.DoLookup()

		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Printf("%+v\n", res)
			// isCloud := cloud.UpdateCloudServices(res.IPAddr)
			cloud.UpdateCloudServices()
		}
	}

	domainFile.Close()

}
