use reqwest::Client;
use std::fs;
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;
use std::time::Duration;
use tokio::time::timeout;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::atomic::{AtomicUsize, Ordering};
use lazy_static::lazy_static;

lazy_static! {
    static ref HTTP_CLIENT: Client = Client::new();
}

pub async fn scan_subdomains(
    url_template: String, 
    wordlist_path: &str,
    ip_address: Option<String>,
    thread_count: usize,
    processed_requests: Arc<AtomicUsize>,
    _filtered_requests: Arc<AtomicUsize>
) -> Result<(), Box<dyn std::error::Error>> {
    match &ip_address {
        Some(ip) => println!("IP Address specified: {}", ip),
        None => println!("No IP Address specified."),
    }
    println!("url_template: {}", url_template);
    println!("wordlist_path: {}", wordlist_path);
    println!("thread_count: {}\n", thread_count);

    let wordlist_data = fs::read_to_string(wordlist_path)?;
    let total_requests = wordlist_data.lines().count();

    println!("==============================================================================================");
    println!("{: <10} {: <10} {: <10} {: <10} {: <12} {: <50}", "ID", "Response", "Lines", "Words", "Chars", "Payload");
    println!("==============================================================================================");

    let progress_bar = ProgressBar::new(total_requests as u64);
    progress_bar.set_style(ProgressStyle::default_bar()
        .template("\n{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} - {msg}")
        .progress_chars("#>-"));
    let progress_bar = Arc::new(Mutex::new(progress_bar));

    let semaphore = Arc::new(Semaphore::new(thread_count));
    let wordlist: Arc<Vec<String>> = Arc::new(wordlist_data.lines().map(String::from).collect());
    let tasks: Vec<_> = (0..wordlist.len()).map(|id| {
        let word = wordlist[id].clone();
        let semaphore_clone = semaphore.clone();
        let progress_bar_clone = progress_bar.clone();
        let url_template = url_template.clone();
        let processed_requests = processed_requests.clone();

        tokio::spawn(async move {
            let _permit = semaphore_clone.acquire_owned().await.expect("Failed to acquire semaphore permit");
            let client = HTTP_CLIENT.clone();
            let url = url_template.replace("fuzz.", &(word.to_owned() + "."));
            let request = client.get(&url).send();

            match timeout(Duration::from_secs(10), request).await {
                Ok(Ok(resp)) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    let lines = body.lines().count();
                    let words = body.split_whitespace().count();
                    let chars = body.chars().count();

                    let pb = progress_bar_clone.lock().expect("Lock poisoned");
                    pb.println(format!("{: <12} {: <15} {: <10} {: <10} {: <12} {: <50}", 
                    id, 
                    status, 
                    lines, 
                    words, 
                    chars, 
                    word));
                },
                Ok(Err(_e)) => {
                    // println!("Error making request: {}", e);
                },
                Err(_) => {
                    // println!("Request timed out. {}", url);
                }
            }

            processed_requests.fetch_add(1, Ordering::Relaxed);
        })
    }).collect();

    for task in tasks {
        task.await?;
    }

    let pb = progress_bar.lock().expect("Lock poisoned");
    pb.finish_and_clear();

    Ok(())
}
