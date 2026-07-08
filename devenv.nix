{
  pkgs,
  lib,
  config,
  inputs,
  ...
}:

{
  languages = {
    go = {
      enable = true;
      package = pkgs.go_1_26;
    };
  };

  packages = [
    pkgs.clang_19
    pkgs.llvm_19
    pkgs.gnumake
    pkgs.nodejs
  ];

  env = {
    CLANG = "clang";
    STRIP = "llvm-strip";
  };

  treefmt = {
    enable = true;
    config.programs = {
      nixfmt.enable = true;
      gofmt.enable = true;
      shfmt.enable = true;
    };
  };

  enterTest = ''
    echo "Running devenv tests"
    go version | grep -E "go1\.2[6-9]"
    clang --version | grep "clang version 19"
    llvm-strip --version | grep "LLVM version 19"
    treefmt --version
  '';
}
