# GoCloud

If you need to find out whether a domain resolves to a cloud hosted such as AWS, Azure, Cloudflare, etc, then you can put all of the domains into a file and run GoCloud which will let you know whether they resolve to a cloud service.

## Install

```
git clone https://github.com/MantisSTS/GoCloud.git
cd GoCloud
go build .
./GoCloud -df domains.txt
```

## Supported Cloud Services

The following Cloud Services are currently supported:

- Google Cloud
- Cloudflare
- Amazon Web Services (AWS)
- Microsoft Azure


## Usage

**Nameservers**

You can specify a set of nameservers `nameservers.txt` to use which may be useful if you have many domains to check.


**Latest Cloud IPs**

Run the program with the `-update` flag to download the latest IP ranges. This isn't done every time to save time on each run.

```
./GoCloud -update 
```

**Usage**

Put all the domains into a file (`domains.txt` for example) and run the program:

```
./GoCloud -df domains.txt 
```

**Output to File**

GoCloud will output the results to a JSON file when using the `-o` flag:

```
./GoCloud -df domains.txt -nf nameservers.txt -o results.json
```


![image](https://user-images.githubusercontent.com/818959/208897747-1be861b4-e2b0-4949-a1ff-72eea56ea965.png)


## Todo

1. Merge all the IP ranges per service instead of having multiple entries. I know why this happens but just need to fix it