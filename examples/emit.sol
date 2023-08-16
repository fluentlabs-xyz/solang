contract a {
    event foo(bool b) anonymous;

    function emit_event()  public {
        emit foo(true);
    }
}