
        contract b {
            function step1(address j) public returns (uint128) {
                return j.balance;
            }
        }
// ---- Expect: diagnostics ----
// warning: 3:13-63: function can be declared 'view'
