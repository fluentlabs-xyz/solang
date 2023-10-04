contract Test {
    uint32 length = 1;

    function contfunc() public view returns (uint64[]) {
        uint64[] values = new uint64[](length);
//        uint64[3] values = [1, 2, 3];
        values[0] = 5;
        return values;
    }
}