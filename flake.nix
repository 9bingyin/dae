{
  description = "dae development shell";

  inputs = {
    nixpkgs.url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.zst";
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [ inputs.treefmt-nix.flakeModule ];
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      perSystem =
        { pkgs, ... }:
        let
          llvmPackages = pkgs."llvmPackages_${builtins.getEnv "CLANG_VERSION"}" or pkgs.llvmPackages;
        in
        {
          treefmt.programs = {
            nixfmt.enable = true;
            gofmt.enable = true;
            shfmt.enable = true;
          };

          devShells.default = pkgs.mkShell {
            shellHook = ''
              export STRIP=llvm-strip
            '';
            packages = [
              pkgs.go
              llvmPackages.clang-unwrapped
              llvmPackages.llvm
              pkgs.gnumake
              pkgs.nodejs
            ];
          };
        };
    };
}
