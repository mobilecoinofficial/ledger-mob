fn main() -> anyhow::Result<()> {
    let mut cfg = prost_build::Config::new();
    // Replace maps with btree for no_std
    cfg.btree_map(&["."]);

    cfg.compile_protos(&["mob.proto"], &["./"])?;

    Ok(())
}
