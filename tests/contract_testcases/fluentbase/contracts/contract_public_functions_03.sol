abstract contract a {
    uint256 private foo;
}

contract b {
    uint256 public foo;
}

contract c {
    uint256 private foo;
}

// ---- Expect: diagnostics ----
// warning: 2:5-24: storage variable 'foo' has never been used
// warning: 10:5-24: storage variable 'foo' has never been used