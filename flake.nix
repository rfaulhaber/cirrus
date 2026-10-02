{
  description = "cirrus";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs @ {
    self,
    flake-parts,
    ...
  }: let
    projectName = "cirrus";
  in
    flake-parts.lib.mkFlake {inherit inputs;} {
      imports = [];
      flake.overlays.rustOverlay = inputs.rust-overlay.overlays.default;
      systems = [
        "x86_64-linux"
        "aarch64-darwin"
        "aarch64-linux"
      ];

      perSystem = {
        config,
        self',
        inputs',
        pkgs,
        system,
        ...
      }: {
        _module.args.pkgs = import inputs.nixpkgs {
          inherit system;
          overlays = [
            self.overlays.rustOverlay
          ];
        };

        formatter = pkgs.alejandra;

        packages = {
          ${projectName} = pkgs.rustPlatform.buildRustPackage {
            pname = projectName;
            # The root manifest is a virtual workspace manifest (no [package]
            # table) — take the version from the primary crate instead.
            version = let file = builtins.fromTOML (builtins.readFile ./crates/cirrus/Cargo.toml); in file.package.version;
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
          };
          default = self'.packages.${projectName};
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            rust-bin.stable.latest.default
            clippy
            rust-analyzer
            cargo-nextest
            cargo-release
            cargo-deny
            # for salesforce docs skill
            nodejs
          ];
        };
      };

      flake = {};
    };
}
