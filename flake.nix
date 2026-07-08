{
  description = "dae development shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    treefmt-nix.url = "github:numtide/treefmt-nix";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      treefmt-nix,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        clangVersion = builtins.getEnv "CLANG_VERSION";
        llvmPackages =
          if clangVersion == "" then
            pkgs.llvmPackages_19
          else
            pkgs."llvmPackages_${clangVersion}" or pkgs.llvmPackages_19;
        treefmtEval = treefmt-nix.lib.evalModule pkgs {
          projectRootFile = "flake.nix";
          programs = {
            nixfmt.enable = true;
            gofmt.enable = true;
            shfmt.enable = true;
          };
        };
      in
      {
        formatter = treefmtEval.config.build.wrapper;
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.go_1_26
            llvmPackages.clang-unwrapped
            llvmPackages.llvm
            pkgs.gnumake
            pkgs.nodejs
          ];

          shellHook = ''
            export CLANG=clang
            export STRIP=llvm-strip
          '';
        };
      }
    );
}
