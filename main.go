package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	color "github.com/fatih/color"
)

type DNSLookup struct {
	DomainName string
	Nameserver string
	IPAddrs    []string
}

type CloudServices struct {
	Services []CloudService
}

type CloudService struct {
	Name    string
	IPRange []string
}
type ProgArgs struct {
	DomainFile          string
	NSFile              string
	OutputFile          string
	UpdateCloudServices bool
	Threads             int
}

type Output struct {
	Domain  string
	IPAddr  string
	Service string
	IsCloud bool
}

var (
	cloud        CloudServices
	nameservers  []string
	ipRangesFile = "ip-ranges.json"
	output       []Output
)

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
	dns.IPAddrs, err = r.LookupHost(context.Background(), dns.DomainName)

	return dns, err
}

func (c *CloudServices) IsCloud(ip string) bool {
	for _, service := range c.Services {
		for _, rangeIP := range service.IPRange {
			if rangeIP == ip {
				return true
			}
		}
	}
	return false
}

func (c *CloudServices) ReadCloudServices() (CloudServices, error) {

	// Open input file, if it doesn't exist then create it
	file, err := os.OpenFile(ipRangesFile, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		log.Println(err)
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		log.Println(err)
	}

	err = json.Unmarshal(data, c)
	if err != nil {
		log.Println(err)
	}

	return *c, nil
}

func (c *CloudServices) IsCloudIP(ip net.IP) (bool, string, error) {
	for _, service := range c.Services {
		for _, rangeIP := range service.IPRange {
			_, ipRange, _ := net.ParseCIDR(rangeIP)
			if ipRange.Contains(ip) {
				return true, service.Name, nil
			}
		}
	}
	return false, "", nil
}

func (c *CloudServices) CloudServiceFileExists() bool {
	file, err := os.OpenFile(ipRangesFile, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return false
	}
	defer file.Close()
	return true
}

func (c *CloudServices) UpdateCloudServices() {
	// fmt.Println("[+] Updating cloud services IP ranges...(Program will exit after updates)")

	// create local file for writing
	file, err := os.OpenFile(ipRangesFile, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	urls := make(map[string]string)
	urls["AWS"] = "https://ip-ranges.amazonaws.com/ip-ranges.json"
	urls["Cloudflare"] = "https://www.cloudflare.com/ips-v4"
	urls["Cloudflare6"] = "https://www.cloudflare.com/ips-v6"
	urls["Azure"] = fmt.Sprintf("https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_%s.json", GetMicrosoftDate())
	urls["Google"] = "https://www.gstatic.com/ipranges/goog.json"

	var wg sync.WaitGroup
	// Parse the JSON
	for name, url := range urls {

		fmt.Println("[+] Fetching IP ranges for", name)
		wg.Add(1)

		go func(name string, url string) {
			defer wg.Done()

			res, err := http.Get(url)

			if res.StatusCode != 200 {
				fmt.Println("[-] Error fetching IP ranges for", name)
				return
			}

			// fmt.Println("[+] Fetching IP ranges for", name)
			if err != nil {
				panic(err)
			}

			switch name {
			case "Google":
				type GoogleIPRanges struct {
					SyncToken    string `json:"syncToken"`
					CreationTime string `json:"creationTime"`
					Prefixes     []struct {
						IPv4Prefix string `json:"ipv4Prefix,omitempty"`
						IPv6Prefix string `json:"ipv6Prefix,omitempty"`
					} `json:"prefixes"`
				}

				var google GoogleIPRanges
				err = json.NewDecoder(res.Body).Decode(&google)
				if err != nil {
					panic(err)
				}

				for _, prefix := range google.Prefixes {
					if prefix.IPv4Prefix != "" {
						c.Services = append(c.Services, CloudService{Name: name, IPRange: []string{prefix.IPv4Prefix}})
					}
					if prefix.IPv6Prefix != "" {
						c.Services = append(c.Services, CloudService{Name: name, IPRange: []string{prefix.IPv6Prefix}})
					}
				}

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
				var ipv4 []string
				for _, prefix := range aws.Prefixes {
					ipv4 = append(ipv4, prefix.IPPrefix)
				}
				c.Services = append(c.Services, CloudService{Name: name, IPRange: ipv4})

				var ipv6 []string
				for _, prefix := range aws.Ipv6Prefixes {
					ipv6 = append(ipv6, prefix.IPPrefix)
				}
				c.Services = append(c.Services, CloudService{Name: name, IPRange: ipv6})

			case "Cloudflare":
				scanner := bufio.NewScanner(res.Body)
				scanner.Split(bufio.ScanLines)
				var ips []string
				for scanner.Scan() {
					ips = append(ips, scanner.Text())
				}
				c.Services = append(c.Services, CloudService{Name: name, IPRange: ips})

			case "Cloudflare6":
				scanner := bufio.NewScanner(res.Body)
				scanner.Split(bufio.ScanLines)
				var ips []string
				for scanner.Scan() {
					ips = append(ips, scanner.Text())
				}
				c.Services = append(c.Services, CloudService{Name: name, IPRange: ips})

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
					c.Services = append(c.Services, CloudService{Name: name, IPRange: prefix.Properties.AddressPrefixes})
				}
			}
		}(name, url)
	}
	wg.Wait()

	// Write the results to the file in JSON format
	b, err := json.MarshalIndent(c, "", "	")
	if err != nil {
		panic(err)
	}

	_, err = file.Write(b)
	if err != nil {
		panic(err)
	}

}

// Get the date of the most recent monday - This is used for the Microsoft IP ranges
func GetMicrosoftDate() string {
	t := time.Now()
	weekday := int(t.Weekday())
	if weekday == 0 {
		weekday = 7
	}
	monday := t.AddDate(0, 0, -weekday+1)
	return strings.ReplaceAll(monday.Format("2006-01-02"), "-", "")
}

func processQueue(queue chan string, wg *sync.WaitGroup) {

	defer wg.Done()

	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)

	var dns DNSLookup
	for domain := range queue {
		dns.DomainName = domain
		dns.Nameserver = nameservers[rand.Intn(len(nameservers))]
		res, err := dns.DoLookup()

		if err != nil {
			fmt.Println(err)
		}

		for _, ip := range res.IPAddrs {

			isCloud, service, err := cloud.IsCloudIP(net.ParseIP(ip))

			if err != nil {
				fmt.Println(err)
			} else {
				if isCloud {
					green.Printf("[+] Is Cloud Service: %t | Service: %s | IP: %s | Domain: %s\n", isCloud, service, ip, domain)
				} else {
					red.Printf("[-] Is Cloud Service: %t | IP: %s | Domain: %s\n", isCloud, ip, domain)
				}
				output = append(output, Output{Domain: domain, IPAddr: ip, Service: service, IsCloud: isCloud})
			}
		}
	}
}

func main() {

	args := ProgArgs{}

	// Create a flag to read the domain name from a file or from the command line
	flag.StringVar(&args.DomainFile, "df", "", "File containing domains to lookup")
	flag.StringVar(&args.NSFile, "nf", "nameservers.txt", "File containing nameservers to use for lookup")
	flag.StringVar(&args.OutputFile, "o", "", "Output File (JSON)")
	flag.IntVar(&args.Threads, "t", 10, "Number of threads to use")
	flag.BoolVar(&args.UpdateCloudServices, "update", false, "Update the cloud service IP ranges - Please run this first and then run the program again without this flag")
	flag.Parse()

	if args.NSFile == "" && !args.UpdateCloudServices {
		fmt.Println("Please specify a nameserver file")
		os.Exit(1)
	}

	// Check if the ip-ranges.json file exists
	_, err := os.Stat("ip-ranges.json")
	if os.IsNotExist(err) {
		args.UpdateCloudServices = true
	}

	if args.UpdateCloudServices {
		cloud.UpdateCloudServices()
		fmt.Println("[+] Cloud Services Updated")
		os.Exit(0)
	}

	cloud.ReadCloudServices()

	var wg sync.WaitGroup
	queueChan := make(chan string, 100)

	// Read the nameservers from the file
	nameserverFile, err := os.OpenFile(args.NSFile, os.O_RDONLY|os.O_CREATE, 0644)
	if err != nil {
		panic(err)
	}

	nsScanner := bufio.NewScanner(nameserverFile)
	nsScanner.Split(bufio.ScanLines)
	for nsScanner.Scan() {
		nameservers = append(nameservers, nsScanner.Text())
	}
	nameserverFile.Close()

	for i := 0; i < args.Threads; i++ {
		wg.Add(1)
		go processQueue(queueChan, &wg)
	}

	if args.DomainFile == "" {
		// read from stdin
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			queueChan <- scanner.Text()
		}
	} else {

		// Read the domain names from the file
		domainFile, err := os.Open(args.DomainFile)
		if err != nil {
			panic(err)
		}

		dfScanner := bufio.NewScanner(domainFile)
		dfScanner.Split(bufio.ScanLines)
		for dfScanner.Scan() {
			queueChan <- dfScanner.Text()
		}

		domainFile.Close()
	}

	close(queueChan)

	// This was less than an ideal solution so I will revisit this later

	wg.Wait()

	// Encode the output to JSON and write to a file
	if args.OutputFile != "" {
		b, err := json.MarshalIndent(output, "", "	")
		if err != nil {
			panic(err)
		}

		outputFile, err := os.OpenFile(args.OutputFile, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			panic(err)
		}

		_, err = outputFile.Write(b)
		if err != nil {
			panic(err)
		}

		outputFile.Close()
	}
}
