contract flipper {
	bool private value;
	uint private mul;
	uint private gasss;
	address private add;
	uint private balance;
	uint private gas_left;

	/// Constructor that initializes the `bool` value to the given `init_value`.
	constructor(bool initvalue) {
		value = initvalue;
	}

	/// A message that can be called on instantiated contracts.
	/// This one flips the value of the stored `bool` from `true`
	/// to `false` and vice versa.
	function flip() public {
		value = !value;
	}

	/// Simply returns the current value of our `bool`.
	function get() public view returns (bool) {
		return value;
	}
}
