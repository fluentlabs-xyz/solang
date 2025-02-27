Polkadot
========

Solang works on Polkadot Parachains integrating a recent version of the ``contracts`` pallets.
Solidity flavored for the Polkadot target has the following differences to Ethereum Solidity:

- The address type is 32 bytes, not 20 bytes. This is what Substrate calls an "account".
- An address literal has to be specified using the ``address"5GBWmgdFAMqm8ZgAHGobqDqX6tjLxJhv53ygjNtaaAn3sjeZ"`` syntax
- ABI encoding and decoding is done using the `SCALE <https://docs.substrate.io/reference/scale-codec/>`_ encoding
- Constructors can be named. Constructors with no name will be called ``new`` in the generated metadata.
- There is no ``ecrecover()`` builtin function, or any other function to recover or verify cryptographic signatures at runtime
- Only functions called via rpc may return values; when calling a function in a transaction, the return values cannot be accessed
- An `assert()`, `require()`, or `revert()` executes the wasm unreachable instruction. The reason code is lost

There is a solidity example which can be found in the
`examples <https://github.com/hyperledger/solang/tree/main/examples>`_
directory. Write this to flipper.sol and run:

.. code-block:: bash

  solang compile --target polkadot flipper.sol

Now you should have a file called ``flipper.contract``. The file contains both the ABI and contract wasm.
It can be used directly in the
`Contracts UI <https://contracts-ui.substrate.io/>`_, as if the contract was written in ink!.

Builtin Imports
________________

Some builtin functionality is only available after importing. The following types
can be imported via the special import file ``polkadot``.

.. code-block:: solidity

    import {Hash} from 'polkadot';
    import {chain_extension} from 'polkadot';

Note that ``{Hash}`` can be omitted, renamed or imported via
import object.

.. code-block:: solidity

    // Now Hash will be known as InkHash
    import {Hash as InkHash} from 'polkadot';

.. note::

    The import file ``polkadot`` is only available when compiling for the Polkadot target.

Call Flags
__________

The Substrate contracts pallet knows several 
`flags <https://github.com/paritytech/substrate/blob/6e0059a416a5768e58765a49b33c21920c0b0eb9/frame/contracts/src/wasm/runtime.rs#L392>`_ 
that can be used when calling other contracts.

Solang allows a ``flags`` call argument of type ``uint32`` in the ``address.call()`` function to set desired flags.
By default (if this argument is unset), no flag will be set.

The following example shows how call flags can be used:

.. include:: ../examples/polkadot/call_flags.sol
  :code: solidity

