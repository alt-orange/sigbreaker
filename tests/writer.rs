use sigbraker::writer::write_atomic;

#[test]
fn atomic_output_replaces_complete_file_and_cleans_up_failed_publish() {
    let dir = std::env::temp_dir().join(format!("sigbraker-writer-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("out.exe");
    std::fs::write(&file, b"original").unwrap();
    write_atomic(&file, b"complete replacement").unwrap();
    assert_eq!(std::fs::read(&file).unwrap(), b"complete replacement");
    let directory_target = dir.join("directory");
    std::fs::create_dir_all(&directory_target).unwrap();
    assert!(write_atomic(&directory_target, b"cannot replace a directory").is_err());
    assert!(directory_target.is_dir());
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
    std::fs::remove_file(file).unwrap();
    std::fs::remove_dir(directory_target).unwrap();
    std::fs::remove_dir(dir).unwrap();
}
