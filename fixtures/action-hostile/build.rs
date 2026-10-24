// Inert fixture. If a build ever runs this, it leaves a visible marker.
fn main() {
    let _ = std::fs::write("HOSTILE_BUILD_RS_RAN", "this build script should never run");
}
