abstract contract test {
            address foo = address"5GBWmgdFAMqm8ZgAHGobqDqX6tjLxJhv53ygjNtaaAn3sjeZ";
        }
// ---- Expect: diagnostics ----
// error: 2:27-84: address literal 5GBWmgdFAMqm8ZgAHGobqDqX6tjLxJhv53ygjNtaaAn3sjeZ incorrect length of 35
