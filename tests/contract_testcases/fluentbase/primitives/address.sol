contract test {
            address  foo = 0x1844674_4073709551616;
        }
// ---- Expect: diagnostics ----
// error: 2:28-51: expected 'address', found integer
