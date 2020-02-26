use std::error::Error;
use std::io::Write;
use std::process::{Command, Stdio};

fn test_oras() -> usize {
    let mut child_process = Command::new("oras")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let output = child_process.wait_with_output().unwrap();
    println!("{}", String::from_utf8_lossy(&output.stdout));
    let check = String::from_utf8_lossy(&output.stdout)
        .split_ascii_whitespace()
        .filter(|line| *line == "Usage:")
        .count();

    check
}

#[cfg(test)]
mod tests {
    use crate::test_oras;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn oras_works() {
        assert_eq!(test_oras(), 1);
    }
}
