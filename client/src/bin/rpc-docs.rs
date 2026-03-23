use spaces_client::rpc_schema;

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    match arg.as_str() {
        "--json" => {
            let spec = rpc_schema::full_spec();
            println!("{}", serde_json::to_string_pretty(&spec).unwrap());
        }
        _ => {
            print!("{}", rpc_schema::to_markdown());
        }
    }
}
