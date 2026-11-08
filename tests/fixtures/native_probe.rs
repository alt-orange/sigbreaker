use std::env;

#[inline(never)]
fn fibonacci(n: u32) -> u64 {
    let (mut a, mut b) = (0u64, 1u64);
    for _ in 0..n {
        (a, b) = (b, a.wrapping_add(b));
    }
    a
}

#[inline(never)]
fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    let mut d = 2;
    while d <= n / d {
        if n % d == 0 {
            return false;
        }
        d += 1;
    }
    true
}

#[inline(never)]
fn run(args: &[String]) -> Result<(), &'static str> {
    match args.get(1).map(String::as_str).unwrap_or("") {
        "sum" | "sort" => {
            let mut numbers: Vec<i64> = args[2..]
                .iter()
                .map(|s| s.parse::<i64>())
                .collect::<Result<_, _>>()
                .map_err(|_| "invalid integer")?;
            if args[1] == "sum" {
                println!("{}", numbers.iter().copied().sum::<i64>());
            } else {
                numbers.sort_unstable();
                println!("{}", numbers.iter().map(i64::to_string).collect::<Vec<_>>().join(","));
            }
        }
        "fib" => {
            let n = args.get(2).ok_or("missing integer")?.parse().map_err(|_| "invalid integer")?;
            println!("{}", fibonacci(n));
        }
        "primes" => {
            let n: u64 = args.get(2).ok_or("missing integer")?.parse().map_err(|_| "invalid integer")?;
            println!("{}", (0..=n).filter(|&v| is_prime(v)).count());
        }
        "unwind" => {
            std::panic::set_hook(Box::new(|_| {}));
            if std::panic::catch_unwind(|| panic!("controlled probe panic")).is_err() {
                println!("caught");
            } else {
                return Err("panic was not caught");
            }
        }
        _ => return Err("unknown command"),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run(&env::args().collect::<Vec<_>>()) {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}
