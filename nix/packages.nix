{ sources ? import ./sources.nix
, pkgs ? import sources.nixpkgs { overlays = [ (import sources.nixpkgs-mozilla) ]; config = { allowUnfree = true; }; }
}:
with pkgs;
rec {
  shell-deps = [
    zstd
    (latest.rustChannels.stable.rust.overrideAttrs (_: {
      extensions = [ "clippy-preview" "rust-src" "rustc-dev" "rustfmt-preview" ];
    }))
    openssl
  ];
}
