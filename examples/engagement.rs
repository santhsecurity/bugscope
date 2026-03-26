use bugscope::{BugscopePaths, EngagementConfig, EngagementStore};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join("bugscope-example-store");
    let paths = BugscopePaths::new(&root);
    std::fs::create_dir_all(paths.engagements_dir())?;

    let engagement_path = EngagementStore::new(paths.clone()).engagement_path("acme");
    std::fs::write(
        &engagement_path,
        r#"
        program_name = "acme"
        platform = "hackerone"
        notes = "Only test assets in the published scope."

        [scope]
        in_scope = ["example.com", "*.example.com"]
        out_of_scope = ["admin.example.com"]

        [credentials]
        handle = "researcher"
        token = "secret"

        [rate_limits]
        default_requests_per_second = 2.0
        "#,
    )?;

    let store = EngagementStore::new(paths);
    let engagement: EngagementConfig = store.load("acme")?;
    println!(
        "{} on {}",
        engagement.program_name,
        engagement.platform.key()
    );
    Ok(())
}
