//! Build script for `satd-events`. Compiles the protobuf schema only when
//! the `grpc` feature is enabled, using a vendored `protoc` so the build
//! does not depend on a system installation.

fn main() {
    if std::env::var_os("CARGO_FEATURE_GRPC").is_some() {
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
            .compile_protos(
                &["proto/satd/events/v1/events.proto"],
                &["proto"],
            )
            .expect("compile satd-events protos");
        println!("cargo:rerun-if-changed=proto/satd/events/v1/events.proto");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
