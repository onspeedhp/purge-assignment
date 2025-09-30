use yellowstone_grpc_client::{GeyserGrpcClient, ClientTlsConfig};
use tracing::info;

pub async fn setup_client(endpoint: String) -> Result<GeyserGrpcClient<impl yellowstone_grpc_client::Interceptor>, Box<dyn std::error::Error>> {
    info!("Connecting to gRPC endpoint: {}", endpoint);

    // Build the gRPC client with TLS config
    let client = GeyserGrpcClient::build_from_shared(endpoint)?
        .tls_config(ClientTlsConfig::new().with_native_roots())?
        .connect()
        .await?;

    Ok(client)
}
