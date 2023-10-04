contract test {
            address foo = address"5GBWmgdFAMqm8ZgAHGobqDqX6tjLxJhv53ygjNtaaAn3sj%Z";
        }
// ---- Expect: diagnostics ----
// error: 2:73: address literal 5GBWmgdFAMqm8ZgAHGobqDqX6tjLxJhv53ygjNtaaAn3sj%Z invalid character '%'
