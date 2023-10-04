contract base {
    modifier foo() virtual {
        _;
    }
}

contract apex is base {
    function foo() public override {}
}
// ---- Expect: diagnostics ----
// error: 8:5-35: function 'foo' overrides modifier
// 	note 2:5-27: previous definition of 'foo'
