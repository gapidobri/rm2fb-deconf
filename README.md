# Automatic Remarkable 2 framebuffer configuration decompiler

This program will automatically decompile the `xochitl` binary and generate `rm2fb.conf` file.

## Installation

Before running this program, you have to install [`radare2`](https://rada.re/n/radare2.html) and [`r2ghidra`](https://github.com/radareorg/r2ghidra) plugin.

Build the program with

```sh
cargo build --release
```

## Running

```sh
./rm2fb-deconf <path_to_xochitl> <version_number> <version_string> -o <optional_output_path>
```

Example

```sh
./rm2fb-deconf ./xochitl 20220921101206 2.14.3.1047
```

I have only tested this script with one version of xochitl. Please report any bugs with newer versions.
