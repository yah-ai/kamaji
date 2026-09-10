// Tells cargo that `YAH_HOTSHIP_VERSION` is an input to this crate's
// compilation, so changing it invalidates a cached build.
//
// Without this, `option_env!` in `server::CONSTABLE_VERSION` would be baked
// into a stale artifact and a hot ship would install a binary still carrying
// the previous stamp — reintroducing the exact "reports a version it does not
// contain" failure the stamp exists to prevent (R746-T3).
fn main() {
    println!("cargo:rerun-if-env-changed=YAH_HOTSHIP_VERSION");
}
