{
  description = "Packet Payload Studio — Tauri 2 + Bundled Python Desktop Application";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        nativeBuildInputs = with pkgs; [
          rustc cargo pkg-config nodejs_22 python312 python312Packages.pyinstaller wrapGAppsHook4
        ];
        buildInputs = with pkgs; [
          webkitgtk_4_1 gtk3 libsoup_3 glib openssl cairo pango gdk-pixbuf librsvg
        ];
      in {
        devShells.default = pkgs.mkShell {
          inherit nativeBuildInputs buildInputs;
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath buildInputs;
        };
      });
}
