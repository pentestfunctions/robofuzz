use colorful::Color;
use colorful::Colorful;
use colorful::HSL;

pub fn print_ascii_title() {
    println!("{}", "██████   ██████  ██████   ██████  ███████  ██████  █████  ███    ██".gradient(Color::Green));
    println!("{}", "██   ██ ██    ██ ██   ██ ██    ██ ██      ██      ██   ██ ████   ██".gradient(Color::Green));
    println!("{}", "██████  ██    ██ ██████  ██    ██ ███████ ██      ███████ ██ ██  ██".gradient(Color::Green));
    println!("{}", "██   ██ ██    ██ ██   ██ ██    ██      ██ ██      ██   ██ ██  ██ ██".gradient(Color::Green));
    println!("{}", "██   ██  ██████  ██████   ██████  ███████  ██████ ██   ██ ██   ████".gradient(Color::Green));
    println!("{}", "___________________________________________________________________".gradient(Color::Green));
    println!("{}", "\nPros: rootfate | doc | langchain | scriptshota | winnievr | delirium_eg".gradient_with_color(HSL::new(0.0, 1.0, 0.5), HSL::new(0.833, 1.0, 0.5)).underlined());
    println!("{}", "Skids: h34p0v3rfl0w | dum3butt | thor0411. | arcticscandiacus | tylerr1".gradient_with_color(HSL::new(0.0, 1.0, 0.5), HSL::new(0.833, 1.0, 0.5)).underlined());
    println!("{}", "MegaSkids: nimscan aka sim0n aka paki jesus aka drone strike aka indian call center".gradient_with_color(HSL::new(0.0, 1.0, 0.5), HSL::new(0.833, 1.0, 0.5)).underlined());
}
