use clap::{App, Arg};
use reqwest::header::HeaderMap;
use std::fs;
use colorful::Color;
use colorful::Colorful;
use std::io::{stdout};
use tokio::sync::{Mutex};
use std::sync::Arc;
mod vhosts;
use vhosts::scan_subdomains;
mod headers;
mod pathfuzz;
use core::sync::atomic::AtomicUsize;
use std::collections::HashSet;
use url::Url;
use std::path::PathBuf;
use crossterm::{execute, terminal::{Clear, ClearType}, cursor::MoveTo};
mod fetch_robots_txt;
use crate::fetch_robots_txt::fetch_robots_and_sitemap;

fn clear_screen() {
    let mut stdout = stdout();
    execute!(
        stdout,
        Clear(ClearType::All),
        MoveTo(0, 0)           
    ).expect("Failed to clear screen and reset cursor position");
}

fn read_wordlist_file(path: &str) -> Result<Vec<u8>, String> {
    let path_buf = PathBuf::from(path);
    println!("Attempting to read from path: {:?}", path_buf.display());

    match fs::canonicalize(&path_buf) {
        Ok(canonical_path) => {
            println!("Canonical path resolved: {:?}", canonical_path.display());

            if !canonical_path.is_file() {
                return Err(format!("Path is not a file: {:?}", canonical_path.display()));
            }

            match fs::read(&canonical_path) {
                Ok(data) => {
                    println!("File read successfully, size: {}", data.len());
                    Ok(data)
                },
                Err(e) => Err(format!("Error reading wordlist file: {}", e))
            }
        },
        Err(e) => Err(format!("Error resolving path '{}': {}", path_buf.display(), e))
    }
}

#[tokio::main]
async fn main() {
    let extra_help = r#"
    Example Usages:

    1. Standard directory scan
        --url "https://example.li/FUZZ" -w wordlist.txt

    2. Standard subdomain scan
        --url "https://FUZZ.example.li/" -w subdomains.txt
    
    3. Directory scan with 2 wordlists and cookies
        --u ".../editor&fileurl=FUZ2ZFUZZ" -w "wordlist.txt" -x "lfi_paths.txt" -c "sid=123123"

    4. VHost/Subdomain scanning against a specific IP address
        --url "https://FUZZ.example.li/" -w subdomains.txt -i 192.168.1.1
    "#;
    let matches = App::new("ROBOT Fuzzer")
        .version("0.1.0")
        .author("Robot <robot@owlsec.ai>")
        .about("Performs web fuzzing with a wordlist.")
        .after_help(extra_help)
        .arg(Arg::new("url")
             .short('u')
             .long("url")
             .takes_value(true)
             .required(true)
             .help("The target URL with 'FUZZ' where the payload should be inserted"))
        .arg(Arg::new("threads")
             .short('t')
             .long("threads")
             .takes_value(true)
             .required(false)
             .default_value("25")
             .help("Number of concurrent threads to use for fuzzing"))
        .arg(Arg::new("wordlist")
             .short('w')
             .long("wordlist")
             .takes_value(true)
             .required(false)
             .default_value("/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt")
             .help("Path to the wordlist file - To use, specify FUZZ in your URL"))
        .arg(Arg::new("wordlist2")
             .short('x')
             .long("wordlist2")
             .takes_value(true)
             .required(false)
             .help("Path to the secondary wordlist file (optional) If used you must specify FUZ2Z in your URL"))
        .arg(Arg::new("cookies")
             .short('c')
             .long("cookies")
             .takes_value(true)
             .help("Cookies to be sent with each request"))
        .arg(Arg::new("ip")
             .short('i')
             .long("ipaddress")
             .takes_value(true)
             .required(false)
             .help("IP Address for VHOST resolution"))
        .arg(Arg::new("help")
             .short('h')
             .long("help")
             .takes_value(false)
             .required(false)
             .help("Prints extra help information about command usage"))
        .get_matches();

    let url = matches.value_of("url").unwrap();
    let ip_address = matches.value_of("ip").map(String::from);
    let threads = matches.value_of("threads").unwrap_or("10").parse::<usize>().unwrap();

    // Wordlist 1
    let wordlist_path = matches.value_of("wordlist").unwrap();
    // Correct handling with a match statement
    let wordlist_bytes = match read_wordlist_file(wordlist_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("{}", error);
            return;
        }
    };

    let wordlist = Arc::new(String::from_utf8_lossy(&wordlist_bytes).into_owned());
    
    // Wordlist 2
    let wordlist2_path = matches.value_of("wordlist2");
    let wordlist2 = wordlist2_path.map(|path| fs::read_to_string(path).expect("Failed to read secondary wordlist file"));
    let wordlist2 = wordlist2.as_ref().map(|s| s.lines().map(String::from).collect::<Vec<_>>());

    // Check if the URL contains "FUZZ"
    if !url.contains("FUZZ") {
        eprintln!("Error: The provided URL must contain the placeholder 'FUZZ'. Please specify the target URL correctly.");
        std::process::exit(1);
    }

    // Header Information
    clear_screen();
    headers::print_ascii_title();
    println!("\n{}\n\n", format!("Target URL: {}", url).gradient(Color::Blue));

    let _client = reqwest::Client::new();
    let mut headers = HeaderMap::new();
    let cookies = matches.value_of("cookies").unwrap_or("");
    if !cookies.is_empty() {
        headers.insert("cookie", reqwest::header::HeaderValue::from_str(cookies).unwrap());
    }
    
    // let semaphore = Arc::new(Semaphore::new(threads));
    let processed_requests = Arc::new(AtomicUsize::new(0));
    let filtered_requests = Arc::new(AtomicUsize::new(0));
    let invalid_signatures = Arc::new(Mutex::new(HashSet::new()));
    let progress_bar = Arc::new(Mutex::new(indicatif::ProgressBar::new(100)));

    // Parse the URL (If subdomain has fuzz, we will run subdomain/vhost enumeration - but if it is in the directory part of the URL it will run directory/path scan)
    // println!("Starting URL scan for: {}", url); // Debugging output for starting URL scan
    if let Ok(parsed_url) = Url::parse(url) {
        let domain = parsed_url.host_str().unwrap_or_default();
        let cleaned_url = format!("{}://{}", parsed_url.scheme(), domain);
    
        let full_path = format!("{}{}", parsed_url.path(), parsed_url.query().unwrap_or("")); 
        let full_path_lower = full_path.to_lowercase();
    
        if domain.starts_with("fuzz.") {
            // Perform subdomain/vhost scan
            // println!("Starting subdomain/vhost scan for: {}", cleaned_url); // Debugging output for subdomain/vhost scan
            if let Err(e) = scan_subdomains(cleaned_url.clone(), wordlist_path, ip_address, threads, processed_requests.clone(), filtered_requests.clone()).await {
                eprintln!("Error scanning subdomains: {}", e);
            }
        } else if full_path_lower.contains("fuzz") {
            println!("Found 'fuzz' in path, fetching robots.txt and sitemap.xml...");
            match fetch_robots_and_sitemap(&url).await {
                Ok(mut sitemap_urls) => {
                   // Trim leading slashes and print URLs
                    sitemap_urls = sitemap_urls.iter().map(|url| url.trim_start_matches('/').to_string()).collect();
                    
                    // Deduplicate
                    let mut wordlist_set: HashSet<_> = sitemap_urls.into_iter().collect();
                    let original_wordlist = String::from_utf8_lossy(&wordlist_bytes).into_owned();
                    original_wordlist.lines().for_each(|line| { wordlist_set.insert(line.to_string()); });
                    
                    let combined_wordlist: Vec<String> = wordlist_set.into_iter().collect();
                    let combined_wordlist_str = combined_wordlist.join("\n");
                    
                    println!("Deduplicated wordlist ready with {} entries.", combined_wordlist.len());
                    
                    // Convert the combined wordlist to Arc<String> for thread-safe usage
                    let combined_wordlist_arc = Arc::new(combined_wordlist_str);
                    
                    // Proceed with the fuzzing operation using the updated wordlist
                    pathfuzz::path_fuzz(&url, &combined_wordlist_arc, wordlist2, &headers, &progress_bar, &processed_requests, &filtered_requests, &invalid_signatures, threads).await;
                },
                Err(e) => {
                    eprintln!("Error fetching robots.txt & sitemap.xml: {}\n", e);
                    pathfuzz::path_fuzz(&url, &wordlist, None, &headers, &progress_bar, &processed_requests, &filtered_requests, &invalid_signatures, threads).await;
                }
            }
        } else {
            eprintln!("'fuzz' not found in the expected location (subdomain or path).");
        }
    } else {
        eprintln!("Failed to parse the URL. Please ensure it's correctly formatted.");
    }
}
