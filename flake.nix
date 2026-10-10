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
          # Every workspace member is a library, so the output holds no
          # binaries; the build's value is the sandboxed test run, which
          # `checks` below exposes to `nix flake check`.
          ${projectName} = pkgs.rustPlatform.buildRustPackage {
            pname = projectName;
            # The root manifest is a virtual workspace manifest (no [package]
            # table) — take the version from the primary crate instead.
            version = let file = builtins.fromTOML (builtins.readFile ./crates/cirrus/Cargo.toml); in file.package.version;
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            # reqwest's rustls platform verifier loads the OS trust store
            # when a client is built and fails when it finds no roots. The
            # sandbox has none, and stdenv points SSL_CERT_FILE at a file
            # that does not exist; cacert's setup hook repoints it at the
            # bundled roots, so the tests can build their clients.
            nativeCheckInputs = [pkgs.cacert];
          };
          default = self'.packages.${projectName};
        };

        checks.${projectName} = self'.packages.${projectName};

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            rust-bin.stable.latest.default
            clippy
            rust-analyzer
            cargo-nextest
            cargo-release
            cargo-deny
            # for the per-crate feature matrix CI runs (cargo hack check)
            cargo-hack
            # for salesforce docs skill
            nodejs
          ];
        };
      };

      flake = {};
    };
}
