//! gRPC server implementation

use crate::grpc::conversions::parse_clock_identity;
use crate::grpc::proto;
use crate::grpc::proto::ptp_service_server::{PtpService as PtpServiceTrait, PtpServiceServer};
use crate::grpc::static_files;
use crate::service::{PtpEvent, PtpService};
use anyhow::Result;
use axum::{
    Router,
    extract::Request as AxumRequest,
    http::{StatusCode, Uri, header},
    response::{Html, IntoResponse},
};
use http_body_util::BodyExt;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tonic_web::GrpcWebLayer;
use tower::ServiceExt;

/// gRPC service implementation
pub struct GrpcService {
    ptp_service: Arc<dyn PtpService>,
}

impl GrpcService {
    pub fn new(ptp_service: Arc<dyn PtpService>) -> Self {
        Self { ptp_service }
    }
}

#[tonic::async_trait]
impl PtpServiceTrait for GrpcService {
    async fn list_hosts(
        &self,
        _request: Request<proto::ListHostsRequest>,
    ) -> Result<Response<proto::ListHostsResponse>, Status> {
        let hosts = self
            .ptp_service
            .get_hosts()
            .await
            .map_err(|e| Status::internal(format!("Failed to get hosts: {}", e)))?;

        let proto_hosts: Vec<proto::Host> = hosts.iter().map(|h| h.into()).collect();

        Ok(Response::new(proto::ListHostsResponse {
            hosts: proto_hosts,
        }))
    }

    async fn get_host(
        &self,
        request: Request<proto::GetHostRequest>,
    ) -> Result<Response<proto::GetHostResponse>, Status> {
        let clock_id_str = &request.get_ref().clock_identity;
        let clock_id = parse_clock_identity(clock_id_str)
            .map_err(|e| Status::invalid_argument(format!("Invalid clock identity: {}", e)))?;

        let host = self
            .ptp_service
            .get_host_by_id(&clock_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get host: {}", e)))?;

        match host {
            Some(h) => Ok(Response::new(proto::GetHostResponse {
                host: Some((&h).into()),
            })),
            None => Err(Status::not_found("Host not found")),
        }
    }

    type StreamHostsStream = Pin<Box<dyn Stream<Item = Result<proto::HostEvent, Status>> + Send>>;

    async fn stream_hosts(
        &self,
        _request: Request<proto::StreamHostsRequest>,
    ) -> Result<Response<Self::StreamHostsStream>, Status> {
        let mut event_rx = self
            .ptp_service
            .subscribe_to_events()
            .await
            .map_err(|e| Status::internal(format!("Failed to subscribe to events: {}", e)))?;

        let (tx, rx) = mpsc::channel(100);

        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                // Only send host-related events
                let proto_event = match &event {
                    PtpEvent::HostDiscovered(_)
                    | PtpEvent::HostUpdated { .. }
                    | PtpEvent::HostTimeout { .. } => Some((&event).into()),
                    _ => None,
                };

                if let Some(evt) = proto_event
                    && tx.send(Ok(evt)).await.is_err() {
                        break;
                    }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    type StreamPacketsStream = Pin<Box<dyn Stream<Item = Result<proto::Packet, Status>> + Send>>;

    async fn stream_packets(
        &self,
        request: Request<proto::StreamPacketsRequest>,
    ) -> Result<Response<Self::StreamPacketsStream>, Status> {
        let req = request.get_ref();

        // Parse filter clock ID if provided
        let filter_clock_id =
            if let Some(ref clock_id_str) = req.clock_identity {
                Some(parse_clock_identity(clock_id_str).map_err(|e| {
                    Status::invalid_argument(format!("Invalid clock identity: {}", e))
                })?)
            } else {
                None
            };

        let history_only = req.history_only;
        let limit = req.limit as usize;

        // Get historical packets if a specific host is requested
        let historical_packets = if let Some(ref clock_id) = filter_clock_id {
            let mut packets = self
                .ptp_service
                .get_packet_history(clock_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to get packet history: {}", e)))?;

            // Apply limit if specified
            if limit > 0 {
                packets.truncate(limit);
            }
            packets
        } else {
            // If no specific host, we don't have a global packet history
            vec![]
        };

        let (tx, rx) = mpsc::channel(100);

        // If history_only, just send historical packets and close
        if history_only {
            tokio::spawn(async move {
                for packet in historical_packets {
                    let proto_packet: proto::Packet = (&packet).into();
                    if tx.send(Ok(proto_packet)).await.is_err() {
                        break;
                    }
                }
            });
        } else {
            // Send historical packets first, then continue with live streaming
            let mut event_rx =
                self.ptp_service.subscribe_to_events().await.map_err(|e| {
                    Status::internal(format!("Failed to subscribe to events: {}", e))
                })?;

            tokio::spawn(async move {
                // Send historical packets first
                for packet in historical_packets {
                    let proto_packet: proto::Packet = (&packet).into();
                    if tx.send(Ok(proto_packet)).await.is_err() {
                        return;
                    }
                }

                // Then stream new packets
                while let Some(event) = event_rx.recv().await {
                    if let PtpEvent::PacketReceived(packet) = event {
                        // Apply filter if specified
                        if let Some(ref filter_id) = filter_clock_id {
                            let source_id = packet.ptp.header().source_port_identity.clock_identity;
                            if &source_id != filter_id {
                                continue;
                            }
                        }

                        let proto_packet: proto::Packet = (&packet).into();
                        if tx.send(Ok(proto_packet)).await.is_err() {
                            break;
                        }
                    }
                }
            });
        }

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn get_statistics(
        &self,
        _request: Request<proto::GetStatisticsRequest>,
    ) -> Result<Response<proto::GetStatisticsResponse>, Status> {
        let stats = self
            .ptp_service
            .get_statistics()
            .await
            .map_err(|e| Status::internal(format!("Failed to get statistics: {}", e)))?;

        Ok(Response::new(proto::GetStatisticsResponse {
            stats: Some(proto::Statistics {
                total_hosts: stats.total_hosts as u32,
                transmitter_count: stats.transmitter_count as u32,
                receiver_count: stats.receiver_count as u32,
                listening_count: stats.listening_count as u32,
                last_packet_age_ms: stats.last_packet_age_ms,
                total_packets: stats.total_packets,
                hostname: stats.hostname,
                interfaces: stats.interfaces,
                version: stats.version,
            }),
        }))
    }

    async fn clear_hosts(
        &self,
        _request: Request<proto::ClearHostsRequest>,
    ) -> Result<Response<proto::ClearHostsResponse>, Status> {
        // Get count before clearing
        let hosts = self
            .ptp_service
            .get_hosts()
            .await
            .map_err(|e| Status::internal(format!("Failed to get hosts: {}", e)))?;
        let count = hosts.len() as u32;

        self.ptp_service
            .clear_hosts()
            .await
            .map_err(|e| Status::internal(format!("Failed to clear hosts: {}", e)))?;

        Ok(Response::new(proto::ClearHostsResponse {
            cleared_count: count,
        }))
    }
}

/// Serve static files from embedded frontend
async fn serve_static(uri: Uri) -> impl IntoResponse {
    let path = uri.path();

    match static_files::get_asset(path) {
        Some((content, mime_type)) => {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                mime_type
                    .parse()
                    .unwrap_or_else(|_| "application/octet-stream".parse().unwrap()),
            );

            // Add cache headers for assets
            if path.contains("/assets/") {
                headers.insert(
                    header::CACHE_CONTROL,
                    "public, max-age=31536000, immutable".parse().unwrap(),
                );
            } else {
                headers.insert(header::CACHE_CONTROL, "no-cache".parse().unwrap());
            }

            (StatusCode::OK, headers, content.into_owned()).into_response()
        }
        None => {
            // For SPA routing, serve index.html for non-asset paths
            if (!path.contains('.') || path.starts_with("/host/"))
                && let Some((content, _)) = static_files::get_asset("index.html") {
                    let mut headers = axum::http::HeaderMap::new();
                    headers.insert(header::CONTENT_TYPE, "text/html".parse().unwrap());
                    headers.insert(header::CACHE_CONTROL, "no-cache".parse().unwrap());
                    return (StatusCode::OK, headers, content.into_owned()).into_response();
                }

            Html(
                r#"<html><body>
                <h1>Frontend Not Built</h1>
                <p>The web UI is not available yet. Build it with:</p>
                <pre>cd frontend && npm install && npm run build</pre>
                <p>Then rebuild the backend with <code>cargo build --release</code></p>
                </body></html>"#,
            )
            .into_response()
        }
    }
}

/// Start the hybrid web server (serves both gRPC API and web UI)
pub async fn start_grpc_server(addr: String, ptp_service: Arc<dyn PtpService>) -> Result<()> {
    let socket_addr: SocketAddr = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;

    let grpc_service = GrpcService::new(ptp_service);

    println!("Starting web server on {}", socket_addr);
    println!("  Web UI:  http://{}/", socket_addr);
    println!("  API:     http://{}/api/ptp.v1.PtpService/*", socket_addr);

    // Build gRPC service with /api prefix
    let grpc = Server::builder()
        .accept_http1(true)
        .layer(GrpcWebLayer::new())
        .add_service(PtpServiceServer::new(grpc_service))
        .into_service();

    // Create router with gRPC on /api and static files on everything else
    let app = Router::new().fallback(|uri: Uri, req: AxumRequest| async move {
        let path = uri.path();

        // Route /api/* to gRPC (strip /api prefix)
        if path.starts_with("/api/") {
            let new_path = path.strip_prefix("/api").unwrap();
            let (mut parts, body) = req.into_parts();

            // Update the URI to remove /api prefix for gRPC
            let new_uri = if let Some(query) = parts.uri.query() {
                format!("{}?{}", new_path, query)
            } else {
                new_path.to_string()
            };
            parts.uri = new_uri.parse().unwrap();

            // Convert axum body to tonic's expected body type
            let boxed_body = body
                .map_err(|e| Status::internal(format!("Request body error: {}", e)))
                .boxed_unsync();
            let new_req = http::Request::from_parts(parts, boxed_body);

            match grpc.clone().oneshot(new_req).await {
                Ok(res) => res.into_response(),
                Err(e) => {
                    eprintln!("gRPC error: {:?}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, "gRPC error").into_response()
                }
            }
        } else {
            // Serve static files
            serve_static(uri).await.into_response()
        }
    });

    // Start server
    let listener = tokio::net::TcpListener::bind(socket_addr)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to bind to {}: {}", socket_addr, e))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {}", e))?;

    Ok(())
}
