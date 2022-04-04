let
  sources = import ./nix/sources.nix;
  pkgs = (import sources.nixpkgs {
    overlays = [ (import sources.nixpkgs-mozilla) ];
    config = { allowUnfree = true; };
  });
in
pkgs.mkShell {
  nativeBuildInputs = with pkgs; [ pkg-config ];
  buildInputs = (import ./nix/packages.nix { inherit sources pkgs; }).shell-deps;
}
