use std::collections::HashSet;
use reqwest::Client;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use futures::future::join_all;
use indicatif::{ProgressBar, ProgressStyle, HumanDuration};
use reqwest::header::{HeaderMap};
use tokio::sync::{Semaphore, Mutex};
use std::time::{Instant, Duration};
use url::Url;
use std::process::Command;
use colorful::Colorful;

lazy_static::lazy_static! {
    static ref HTTP_CLIENT: Client = Client::builder()
        .pool_idle_timeout(Some(Duration::from_secs(10)))
        .build()
        .expect("Failed to create HTTP client");
}

#[cfg(target_os = "linux")]
fn check_and_run_whatweb(url: &str) {
    if let Ok(output) = Command::new("whatweb").arg("--version").output() {
        if output.status.success() {
            run_whatweb(url);
        } else {
            println!("whatweb is not installed");
        }
    } else {
        println!("Failed to execute whatweb command");
    }
}

#[cfg(not(target_os = "linux"))]
fn check_and_run_whatweb(url: &str) {
    println!("whatweb is not available on this platform");
}

fn run_whatweb(url: &str) {
    if let Ok(parsed_url) = Url::parse(url) {
        let domain = parsed_url.host_str().unwrap_or_default();
        let cleaned_url = format!("{}://{}", parsed_url.scheme(), domain);

        let output = Command::new("whatweb")
            .arg(&cleaned_url)
            .output()
            .expect("Failed to execute whatweb command");

        if output.status.success() {
            println!("{}", String::from_utf8_lossy(&output.stdout));
        } else {
            println!("Failed to execute whatweb");
        }
    } else {
        println!("Failed to parse URL");
    }
}

pub async fn path_fuzz(url: &str, wordlist: &str, wordlist2: Option<Vec<String>>, headers: &HeaderMap, progress_bar: &Arc<Mutex<ProgressBar>>, processed_requests: &Arc<AtomicUsize>, filtered_requests: &Arc<AtomicUsize>, invalid_signatures: &Arc<Mutex<HashSet<(usize, usize, usize)>>>, thread_count: usize) {
    check_and_run_whatweb(url);
    let _started = Instant::now();

    let predefined_values = vec![
        "thispathdoesnotexist",
        "this/path/does/not/exist",
        "this path does not exist",
        "thisfiledoesnotexist.txt",
        "thisfiledoesnotexist.php",
        "thisfiledoesnotexist.xml",
        "http%3A%2F%2Fwww",
        "########",
        "%20",
    ];


    // Section for printing and creating our invalid response signatures for filtering
    //println!("\nDebugging invalid response signatures:");
    //println!("{:<30} | {:<10} | {:<10} | {:<10}", "Predefined Value", "Lines", "Words", "Chars");
    //println!("{:-<30}-+-{:-<10}-+-{:-<10}-+-{:-<10}", "", "", "", "");
    for value in &predefined_values {
        let request_url = url.replace("FUZZ", value);
        match HTTP_CLIENT.get(&request_url).headers(headers.clone()).send().await {
            Ok(response) => {
                match response.text().await {
                    Ok(body) => {
                        let signature = (body.lines().count(), body.split_whitespace().count(), body.chars().count());
                        invalid_signatures.lock().await.insert(signature);
                        //println!(
                        //    "{:<30} | {:<10} | {:<10} | {:<10}",
                        //    value,
                        //    signature.0,
                        //    signature.1,
                        //    signature.2
                        //);
                    }
                    Err(_) => (),
                    // Err(e) => eprintln!("Failed to read response text: {}", e),
                }
            }
            //Err(e) => eprintln!("Failed to send request: {}", e),
            Err(_) => (),
        }
    }
    
    let total_requests = if let Some(wordlist2) = &wordlist2 {
        wordlist.lines().count() * wordlist2.len()
    } else {
        wordlist.lines().count()
    };

    println!("==============================================================================================");
    println!("{: <10} {: <10} {: <10} {: <10} {: <12} {: <50}", "ID", "Response", "Lines", "Words", "Chars", "Payload");
    println!("==============================================================================================");

    progress_bar.lock().await.set_length(total_requests as u64);
    progress_bar.lock().await.set_style(ProgressStyle::default_bar()
        .template("\n{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} - {msg}")
        .progress_chars("#>-"));

    let started = Instant::now();

    let is_invalid_signature = Arc::new(|signature: &(usize, usize, usize), invalid_signatures: &HashSet<(usize, usize, usize)>| -> bool {
        invalid_signatures.iter().any(|&(l, w, c)| {
            let matches = (l == signature.0) as usize +
                          (w == signature.1) as usize +
                          (c == signature.2) as usize;
            matches >= 2
        })
    });

    // Calculate semaphore limit based on the thread count
    let semaphore_limit = thread_count * 4;

    // Initialize semaphore with the calculated limit
    let semaphore = Arc::new(Semaphore::new(semaphore_limit));

    let combinations: Vec<(String, Option<String>)> = if let Some(wordlist2) = &wordlist2 {
        wordlist.lines().flat_map(|word1| {
            wordlist2.iter().map(move |word2| (word1.to_string(), Some(word2.to_string())))
        }).collect()
    } else {
        wordlist.lines().map(|word1| (word1.to_string(), None)).collect()
    };

    let tasks: Vec<_> = combinations.into_iter().enumerate().map(|(id, (word, word2_option))| {
        let sem_clone = semaphore.clone();
        let headers_clone = headers.clone();
        let url_clone = url.to_string();
        let word_clone = word.clone();
        let progress_bar_clone = progress_bar.clone();
        let processed_requests_clone = processed_requests.clone();
        let filtered_requests_clone = filtered_requests.clone();
        let invalid_signatures_clone = invalid_signatures.clone();
        let is_invalid_signature_clone = is_invalid_signature.clone();

        let processed_requests_clone_inner = processed_requests.clone();

        tokio::spawn(async move {
            let _permit = sem_clone.acquire().await.expect("Failed to acquire semaphore permit");
            let request_url = url_clone.replace("FUZZ", &word_clone).replace("FUZ2Z", word2_option.as_deref().unwrap_or(""));
            let response_result = HTTP_CLIENT.get(&request_url).headers(headers_clone).send().await;

            match response_result {
                Ok(response) => {
                    let status_code = response.status().as_u16();
                    let status_str = response.status().as_str().to_string();
                    let body = response.text().await.expect("Failed to read response text");
            
                    let lines = body.lines().count();
                    let words = body.split_whitespace().count();
                    let chars = body.chars().count();
                    let signature = (lines, words, chars);
            
                    if !is_invalid_signature_clone(&signature, &*invalid_signatures_clone.lock().await) {
                        let payload_display = match &word2_option {
                            Some(word2) => format!("{} | {}", word2, &word_clone),
                            None => word_clone.to_string(),
                        };
            
                        let formatted_line = format!(
                            "{: <10} {: <10} {: <10} {: <10} {: <12} {: <50}",
                            format!("{:06}", id + 1),
                            status_str,
                            lines,
                            words,
                            chars,
                            payload_display
                        );
            
                        // Apply color based on the status code category
                        let colored_line = match status_code {
                            200..=299 => formatted_line.green().bold(),
                            300..=399 => formatted_line.yellow().bold(),
                            400 => formatted_line.magenta().bold().bold(),
                            401..=499 => formatted_line.cyan().bold(),
                            500..=599 => formatted_line.red().bold(),
                            _ => formatted_line.white().bold(),
                        };
            
                        let pb = progress_bar_clone.lock().await;
                        pb.println(colored_line.to_string());
                    } else {
                        filtered_requests_clone.fetch_add(1, Ordering::SeqCst);
                    }
                },
                Err(_) => {
                    // println!("Error for request ID {:06}: {}", id + 1, e);
                },
            }

            processed_requests_clone_inner.fetch_add(1, Ordering::SeqCst);
            let completed = processed_requests_clone_inner.load(Ordering::SeqCst);
            let elapsed = started.elapsed();
            let elapsed_secs = elapsed.as_secs_f64();
            let total_processed_requests = processed_requests_clone.load(Ordering::SeqCst);
            let progress_fraction = completed as f64 / total_requests as f64;
            let rps = if elapsed_secs > 0.0 {
                total_processed_requests as f64 / elapsed_secs
            } else {
                0.0
            };
            
            let estimated_total_time = if progress_fraction > 0.0 {
                elapsed.as_secs_f64() / progress_fraction
            } else {
                0.0
            };
            let estimated_remaining_time = estimated_total_time - elapsed.as_secs_f64();
            let pb = progress_bar_clone.lock().await;
            pb.set_position(completed as u64);
            pb.set_message(format!(
                "ETA: {}, RPS: {:.2}",
                HumanDuration(Duration::from_secs_f64(estimated_remaining_time)),
                rps
            ));
            pb.inc(1);
        })
    }).collect();

    join_all(tasks).await;
    let pb = progress_bar.lock().await;
    pb.finish_with_message("Fuzzing completed");

    println!("\nFuzzing completed in {}", HumanDuration(started.elapsed()));
    println!("Processed Requests: {}", processed_requests.load(Ordering::SeqCst));
    println!("Filtered Requests: {}", filtered_requests.load(Ordering::SeqCst));
}
