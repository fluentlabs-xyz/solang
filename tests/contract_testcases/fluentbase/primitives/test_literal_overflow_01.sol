contract test {
            uint16 foo = 0x10000;
        }
// ---- Expect: diagnostics ----
// error: 2:26-33: value 65536 does not fit into type uint16.
