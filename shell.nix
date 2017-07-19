{ pkgs ? import <nixpkgs> {}, ghc ? pkgs.ghc }:

with pkgs;

haskell.lib.buildStackProject {
  name = "pam-stack-shell";
  inherit ghc;
  buildInputs = [ pam ];
}
