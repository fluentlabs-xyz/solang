abstract contract test {
            address foo = 0x5b0Ddf2835f0A76c96D6113D47F6482e51a55487;
        }
// ---- Expect: diagnostics ----
// warning: 2:13-69: storage variable 'foo' has been assigned, but never read
