//! Build script for `satd-events-proto`. Compiles the `satd.events.v1`
//! protobuf schema into client + server tonic stubs, using a vendored `protoc`
//! so the build does not depend on a system installation.
//!
//! This crate is the single codegen site for the wire schema: the server
//! (`satd-events`) and the client SDK (`satd-events-client`) both depend on the
//! types generated here, so the `.proto` has exactly one source of truth.

fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect(
        "vendored protoc binary missing — re-add `protoc-bin-vendored` to build-dependencies",
    );
    // SAFETY: build scripts run single-threaded before any user code.
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/satd/events/v1/events.proto"], &["proto"])
        .expect("compile satd.events.v1 protos");
    println!("cargo:rerun-if-changed=proto/satd/events/v1/events.proto");
    println!("cargo:rerun-if-changed=build.rs");
}
