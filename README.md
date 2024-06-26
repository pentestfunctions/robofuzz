# 🤖 robofuzz 🤖
Path fuzzer made in rust (In Development)

<p align="center">
  <img src="https://github.com/pentestfunctions/robofuzz/blob/main/images/usage.gif">
</p>

[Grab the test release for windws/arch/kali](https://github.com/pentestfunctions/robofuzz/releases)

Then simply 
```bash
chmod +x robofuzz
```

And
```
./robofuzz --help
```

If you want to add it to your path, after making it executable you can do:
```
sudo cp robofuzz /bin/robofuzz
```

This will copy it to your bin folder which will be in your path so you can now just type `robofuzz` to call on it. 

Still a testing release so let me know how it goes.

```
ROBOT Fuzzer 0.1.0
Robot <robot@owlsec.ai>
Performs web fuzzing with a wordlist.

USAGE:
    robofuzz.exe [OPTIONS] --url <url>

OPTIONS:
    -c, --cookies <cookies>        Cookies to be sent with each request
    -h, --help                     Prints extra help information about command usage
    -i, --ipaddress <ip>           IP Address for VHOST resolution
    -t, --threads <threads>        Number of concurrent threads to use for fuzzing [default: 25]
    -u, --url <url>                The target URL with 'FUZZ' where the payload should be inserted
    -V, --version                  Print version information
    -w, --wordlist <wordlist>      Path to the wordlist file - To use, specify FUZZ in your URL
                                   [default:
                                   /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt]
    -x, --wordlist2 <wordlist2>    Path to the secondary wordlist file (optional) If used you must
                                   specify FUZ2Z in your URL


    Example Usages:

    1. Standard directory scan
        --url "https://example.li/FUZZ" -w wordlist.txt

    2. Standard subdomain scan
        --url "https://FUZZ.example.li/" -w subdomains.txt

    3. Directory scan with 2 wordlists and cookies
        --u ".../editor&fileurl=FUZ2ZFUZZ" -w "wordlist.txt" -x "lfi_paths.txt" -c "sid=123123"

    4. VHost/Subdomain scanning against a specific IP address
        --url "https://FUZZ.example.li/" -w subdomains.txt -i 192.168.1.1
```

Notes:
It will try get words from robots.txt and paths from sitemap.xml
It checks signatures for files that wont exist automatically (as well as subdomains) to ensure results are accurate. 

Ideas for future changes:
```
--crawl function (for urls on the page)

JS endpoints
paramfinder (addin)
burpsuite save request loadin

Custom comment extraction?

Compare lowercase results for things like DOWNLOAD and download based on signature to stop useless duplicates.

Analyze URL style that is being fuzzed.
If URL is FUZZ in the first part of the domain, we should use a subdomain list.
If URL is FUZZ in the second part of the URL, we should use a directory wordlist
```
