target remote 127.0.0.1:1234
handle SIGILL nostop pass noprint
add-symbol-file "../vendor/speculos/build/src/launcher" 0xf00001c0
add-symbol-file "./target/nanosplus/release/ledger-mob-fw" 0x40000000
b sample_main
c
