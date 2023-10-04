contract test {
            int8 foo = 0x8_0;
        }
// ---- Expect: diagnostics ----
// error: 2:24-29: value 128 does not fit into type int8.
