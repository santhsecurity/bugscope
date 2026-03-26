use bugscope::ScopeConfig;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scope: ScopeConfig = toml::from_str(
        r#"
        in_scope = ["example.com", "*.example.com", "192.0.2.0/24"]
        out_of_scope = ["admin.example.com"]
        "#,
    )?;

    println!("{}", scope.is_in_scope("https://api.example.com")?);
    println!("{}", scope.is_in_scope("https://admin.example.com")?);
    Ok(())
}
