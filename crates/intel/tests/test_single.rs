#[tokio::test]
async fn dummy() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    use std::io::Write;
    writeln!(f, "invalid json").unwrap();
    writeln!(f, "{{\"ip\": \"1.1.1.1\", \"port\": 80, \"protocol\": \"tcp\"}}").unwrap();
    f.flush().unwrap();
    
    let path = f.path();
    let file = std::fs::File::open(path).unwrap();
    let reader = std::io::BufReader::new(file);
    use std::io::BufRead;
    for line in reader.lines() {
        println!("Line: {:?}", line);
    }
}
