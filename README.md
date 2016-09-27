# hsainfo
A small program similar to clinfo.

Note that it only works with AMD HSA runtime
(b/c it uses some AMD extensions).

Finds all available HSA devices using the HSA runtime,
and prints some useful info about them.

Tested with AMD ROCm only (not tested with the old HSA
runtime from github.com/HSAfoundation).

To compile just run 'make' (you might need to tweak it,
if your HSA runtime isn't in /opt/rocm/hsa).
