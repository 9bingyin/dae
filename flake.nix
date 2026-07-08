{
  description = "dae development shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
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
      in
      {
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
