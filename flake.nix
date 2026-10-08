{
  description = "Development shell for sandsifter";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          # Python project management (uv fetches its own Python)
          uv

          # Building the injector (Makefile: -lcapstone)
          gcc
          gnumake
          capstone

          # External tools shelled out to by sifter.py / summarize.py / mutator.py
          file        # `file` (injector sanity checks)
          nasm        # `ndisasm`
          binutils    # `objdump`
          which       # `which` (disassembler detection in summarize.py)
          ncurses     # `clear` (summarize.py UI)

          # Shell pipeline tools used in disassembly wrappers
          coreutils   # tr, head, cat, echo
          gnugrep
          gnused
          gawk
        ];
      };
    };
}
