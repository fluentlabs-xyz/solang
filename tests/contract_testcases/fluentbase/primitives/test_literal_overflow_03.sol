contract test {
    int8 foo = -129;
}
// ---- Expect: diagnostics ----
// error: 2:16-20: value -129 does not fit into type int8.
