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
	    uint gas;
    	assembly {
    	    gas := gasprice()
    	}
    	mul = (10 + gas) * 0xfffffffffffffffffffffffffffffe;

		gasss = tx.gasprice(10);

//		assembly {
//			a := address()
//		}
		add = address(this);

		gas_left = gasleft();

		value = !value;
	}

	function get_gas_left() public view returns (uint) {
		return gas_left;
	}

	function get_balance() public view returns (uint) {
		return balance;
	}

	function get_gas() public view returns (uint) {
		return gasss;
	}

    function get_mul() public view returns (uint) {
        return mul;
    }

	function get_address() public view returns (address) {
		return add;
	}

	/// Simply returns the current value of our `bool`.
	function get() public view returns (bool) {
		return value;
	}
}
