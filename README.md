# GoCloud

If you need to find out whether a domain resolves to a cloud hosted such as AWS, Azure, Cloudflare, etc, then you can put all of the domains into a file and run GoCloud which will let you know whether they resolve to a cloud service.

## Install

```
go install -v github.com/MantisSTS/GoCloud@latest
```

## Usage


**Nameservers**

You can specify a set of nameservers `nameservers.txt` to use which may be useful if you have many domains to check.


**Latest Cloud IPs**

Run the program with the `-update` flag to download the latest IP ranges. This isn't done every time to save time on each run.

```
GoCloud -update -df domains.txt
```

**Usage**

Put all the domains into a file (`domains.txt` for example) and run the program:

```
GoCloud -df domains.txt 
```