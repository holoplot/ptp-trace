//! gRPC API for PTP monitoring service
//!
//! This module provides a gRPC API with gRPC-Web support for remote access
//! to the PTP monitoring service.

pub mod conversions;
pub mod server;
pub mod static_files;

// Include the generated protobuf code
pub mod proto {
    tonic::include_proto!("ptp.v1");
}
