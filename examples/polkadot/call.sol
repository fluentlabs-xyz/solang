contract superior {
	function test1() public {
		inferior i = new inferior();

		i.test1();

		assert(keccak256("test1()") == hex"6b59084dfb7dcf1c687dd12ad5778be120c9121b21ef90a32ff73565a36c9cd3");

		bytes bs;
		bool success;

		(success, bs) = address(i).call(hex"6b59084d");

		assert(success == true);
		assert(bs == hex"");
	}

	function test2() public {
		inferior i = new inferior();

		assert(i.test2(257) == 256);

		assert(keccak256("test2(uint64)") == hex"296dacf0801def8823747fbd751fbc1444af573e88de40d29c4d01f6013bf095");

		bytes bs;
		bool success;

		(success, bs) = address(i).call(hex"296dacf0_0101_0000__0000_0000");

		assert(success == true);
		assert(bs == hex"0001_0000__0000_0000");
	}
}

contract inferior {
	function test1() public {
		print("Baa!");
	}

	function test2(uint64 x) public returns (uint64) {
		return x ^ 1;
	}
}