contract b {
    struct foo {
        uint32 f1;
        uint32 f2;
    }
}

contract c {
    enum foo {
        f1,
        f2
    }
}

contract a is b, c {
    function test(foo x) public {}
}

// ---- Expect: diagnostics ----
// error: 2:12-15: already defined 'foo'
// 	note 9:10-13: previous definition of 'foo'
