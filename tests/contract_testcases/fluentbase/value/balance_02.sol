
        contract b {
            function step1(address payable j) public returns (uint128) {
                return j.balance;
            }
        }
// ---- Expect: diagnostics ----
// warning: 3:13-71: function can be declared 'view'
