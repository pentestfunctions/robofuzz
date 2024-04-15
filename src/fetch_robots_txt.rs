use reqwest;
use regex::Regex;
use std::collections::HashMap;
use url::{Url, Position};
use std::collections::HashSet;

pub async fn fetch_robots_and_sitemap(url: &str) -> Result<Vec<String>, reqwest::Error> {
    let client = reqwest::Client::new();
    let robots_url = url.replace("FUZZ", "robots.txt");
    let sitemap_url = url.replace("FUZZ", "sitemap.xml");

    // Fetching robots.txt
    let robots_response = client.get(&robots_url).send().await?;
    if robots_response.status().is_success() {
        let robots_contents = robots_response.text().await?;
        // println!("Contents of {}: {}", robots_url, robots_contents);
        let _robot_urls = extract_paths(&robots_contents);
        let robot_wordlist = create_wordlist(&robots_contents);
        println!("\nRobot Wordlist: {:?}\n", robot_wordlist);
    } else {
        eprintln!("Failed to fetch robots.txt: Status {}", robots_response.status());
    }

    // Fetching sitemap.xml
    let sitemap_response = client.get(&sitemap_url).send().await?;
    if sitemap_response.status().is_success() {
        let sitemap_contents = sitemap_response.text().await?;
        let sitemap_urls = extract_paths(&sitemap_contents);
        // println!("Contents of {}: {}", sitemap_url, sitemap_contents);
        // println!("Sitemap URLs: {:?}", sitemap_urls);
        return Ok(sitemap_urls);
    } else {
        eprintln!("Failed to fetch sitemap.xml: Status {}", sitemap_response.status());
        return Err(sitemap_response.error_for_status().unwrap_err());
    }
}

fn extract_paths(text: &str) -> Vec<String> {
    let mut paths = HashMap::new();
    let re = Regex::new(r#"(?i)<loc>(.*?)</loc>"#).unwrap();
    for caps in re.captures_iter(text) {
        if let Some(url) = caps.get(1) {
            if let Ok(parsed_url) = Url::parse(url.as_str()) {
                let base_url = parsed_url[..Position::BeforeQuery].to_string();
                paths.entry(base_url).or_insert_with(|| {
                    let path = parsed_url.path().to_string();
                    let query = parsed_url.query().map(|q| format!("?{}", q)).unwrap_or_default();
                    path + &query
                });
            }
        }
    }
    paths.values().cloned().collect()
}

fn create_wordlist(text: &str) -> HashSet<String> {
    let mut wordlist = HashSet::new();
    for word in text.split_whitespace() {
        wordlist.insert(word.to_lowercase());
    }
    wordlist
}
