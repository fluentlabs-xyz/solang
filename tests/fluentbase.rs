// SPDX-License-Identifier: Apache-2.0

extern crate core;

/// Mock runtime for the contracts pallet.
use blake2_rfc::blake2b::blake2b;
use contract_metadata::ContractMetadata;
use ink_metadata::InkProject;
use ink_primitives::Hash;
use parity_scale_codec::Decode;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::{collections::HashMap, ffi::OsStr, fmt, fmt::Write};
use std::ptr::write_bytes;
use funty::Numeric;
use itertools::Itertools;
use libc::truncate;
use tiny_keccak::{Hasher, Keccak};
use wasmi::core::{HostError, Trap, TrapCode};
use wasmi::{Engine, Error, Instance, Linker, Memory, MemoryType, Module, Store};

use solang::file_resolver::FileResolver;
use solang::{compile, Target};

use wasm_host_attr::wasm_host;

mod fluentbase_tests;

type StorageKey = [u8; 32];
type Address = [u8; 20];

#[derive(Clone, Copy)]
enum CallFlags {
    ForwardInput = 1,
    CloneInput = 2,
    TailCall = 4,
    AllowReentry = 8,
}

impl CallFlags {
    /// Returns true if this flag is set in the given `flags`.
    fn set(&self, flags: u32) -> bool {
        flags & *self as u32 != 0
    }
}

/// Reason for halting execution. Same as in pallet contracts.
#[derive(Default, Debug, Clone)]
enum HostReturn {
    /// The contract was terminated (deleted).
    #[default]
    Terminate,
    /// Flags and data returned by the contract.
    Data(u32, Vec<u8>),
}

impl HostReturn {
    fn as_data(&self) -> (u32, Vec<u8>) {
        match self {
            HostReturn::Data(flags, data) => (*flags, data.to_vec()),
            HostReturn::Terminate => (0, vec![]),
        }
    }
}

impl fmt::Display for HostReturn {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            Self::Terminate => write!(f, "return: terminate"),
            Self::Data(flags, data) => write!(f, "return {flags} {data:?}"),
        }
    }
}

impl HostError for HostReturn {}

/// Represents a contract code artifact.
#[derive(Clone, Debug)]
pub struct WasmCode {
    /// A mapping from function names to selectors.
    messages: HashMap<String, Vec<u8>>,
    /// A list of the selectors of the constructors.
    constructors: Vec<Vec<u8>>,
    hash: Hash,
    blob: Vec<u8>,
}

impl WasmCode {
    fn new(abi: &str, code: &[u8]) -> Self {
        let abi = load_abi(abi);
        let messages = abi
            .spec()
            .messages()
            .iter()
            .map(|f| (f.label().to_string(), f.selector().to_bytes().to_vec()))
            .collect();
        let constructors = abi
            .spec()
            .constructors()
            .iter()
            .map(|f| f.selector().to_bytes().to_vec())
            .collect();

        Self {
            messages,
            constructors,
            hash: blake2b(32, &[], code).as_bytes().try_into().unwrap(),
            blob: code.to_vec(),
        }
    }
}

/// A `Contract` represent deployed Wasm code with its storage which can be executed.
#[derive(Clone, Debug)]
pub struct Contract {
    code: WasmCode,
    storage: HashMap<StorageKey, Vec<u8>>,
}

impl From<WasmCode> for Contract {
    fn from(code: WasmCode) -> Self {
        Self {
            code,
            storage: HashMap::new(),
        }
    }
}

impl Contract {
    /// Instantiate this contract as a Wasm module for execution.
    fn instantiate(&self, runtime: Runtime) -> Result<(Store<Runtime>, Instance), Error> {
        let engine = Engine::default();
        let mut store = Store::new(&engine, runtime);

        let mut linker = <Linker<Runtime>>::new(&engine);
        Runtime::define(&mut store, &mut linker);
        let memory = Memory::new(&mut store, MemoryType::new(16, Some(16)).unwrap()).unwrap();
        linker.define("env", "memory", memory).unwrap();
        store.data_mut().memory = Some(memory);

        let instance = linker
            .instantiate(&mut store, &Module::new(&engine, &mut &self.code.blob[..])?)?
            .ensure_no_start(&mut store)
            .expect("we never emit a start function");

        Ok((store, instance))
    }

    /// Execute this contract at the exportet function `name` in the given `runtime` context.
    ///
    /// On success, returns the Wasm store including the runtime state is returned.
    /// On failure, returns the Wasm execution Error together with the debug buffer.
    #[allow(clippy::result_large_err)] // eDONTCARE
    fn execute(&self, name: &str, runtime: Runtime) -> Result<Store<Runtime>, (Error, String)> {
        let (mut store, instance) = self.instantiate(runtime).map_err(|e| (e, String::new()))?;

        let func = instance
            .get_export(&store, name)
            .and_then(|export| export.into_func())
            .unwrap_or_else(|| panic!("contract does not export '{name}'"));
        println!("Func: {:?}", func);

        let rs = instance
            .get_export(&store, name)
            .and_then(|export| export.into_func())
            .unwrap_or_else(|| panic!("contract does not export '{name}'"))
            .call(&mut store, &[], &mut []);
        println!("Call rs: {:?}", rs);
        let rs = match rs
        {
            Err(Error::Trap(trap)) if trap.trap_code().is_some() => {
                Err((Error::Trap(trap), store.data().debug_buffer.clone()))
            }
            Err(Error::Trap(trap)) => match trap.downcast::<HostReturn>() {
                Some(HostReturn::Data(flags, data)) => {
                    store.data_mut().output = HostReturn::Data(flags, data);
                    Ok(store)
                }
                Some(HostReturn::Terminate) => Ok(store),
                _ => panic!("contract execution stopped by unexpected trap"),
            },
            Err(e) => panic!("unexpected error during contract execution: {e}"),
            Ok(_) => Ok(store),
        };

        println!("Storage after call: {:?}", self.storage);

        rs
    }
}

/// If contract is `Some`, this is considered to be a "contract account".
#[derive(Default, Clone, Debug)]
struct Account {
    address: Address,
    value: u128,
    contract: Option<Contract>,
}

impl PartialEq for Account {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
    }
}

impl Account {
    /// Create a new contract account.
    /// The account address is derived based of the provided `salt`.
    fn with_contract(salt: &[u8], code: &WasmCode) -> Self {
        Self {
            address: Address::try_from(blake2b(32, &[], salt).as_bytes()[12..].as_ref()).unwrap(),
            contract: Some(code.clone().into()),
            ..Default::default()
        }
    }
}

#[derive(Clone)]
pub struct Event {
    pub data: Vec<u8>,
    pub topics: Vec<Hash>,
}

/// The runtime provides the state of the mocked blockchain node during contract execution.
#[derive(Default, Clone)]
struct Runtime {
    /// A list of "existing" accounts.
    accounts: Vec<Account>,
    /// A list of known ("uploaded") Wasm contract blobs.
    blobs: Vec<WasmCode>,
    /// Index into accounts pointing the account that is being executed.
    account: usize,
    /// Index into accounts pointing to the calling account.
    caller_account: usize,
    /// Will hold the memory reference after a successful execution.
    memory: Option<Memory>,
    /// The input for the contract execution.
    input: Option<Vec<u8>>,
    /// The output of the contract execution.
    output: HostReturn,
    /// Descirbes how much value was given to the contract call.
    transferred_value: u128,
    /// Combined ouptut of all `seal_debug_message` calls
    debug_buffer: String,
    /// Stores all events emitted during contract execution.
    events: Vec<Event>,
    /// The set of called events, needed for reentrancy protection.
    called_accounts: HashSet<usize>,
}

impl Runtime {
    fn new(blobs: Vec<WasmCode>) -> Self {
        Self {
            accounts: blobs
                .iter()
                .map(|blob| Account::with_contract(blob.hash.as_ref(), blob))
                .collect(),
            blobs,
            ..Default::default()
        }
    }

    /// Create a suitable runtime context based on the current one.
    ///
    /// Each contract execution must live within it's own runtime context.
    /// When calling into another contract, we must:
    /// * switch out the caller and callee account
    /// * populate the input and the transferred balance
    /// * clear the output
    fn new_context(&self, callee: usize, input: Vec<u8>, value: u128) -> Self {
        let mut runtime = self.clone();
        runtime.caller_account = self.account;
        runtime.account = callee;
        runtime.transferred_value = value;
        runtime.accounts[callee].value += value;
        runtime.input = Some(input);
        runtime.output = Default::default();
        runtime.called_accounts.insert(self.caller_account);
        runtime
    }

    /// After a succesfull contract execution, merge the runtime context of the callee back.
    ///
    /// We take over accounts (the callee might deploy new ones), debug buffer and emitted events.
    /// The transferred balance will now be deducted from the caller.
    fn accept_state(&mut self, callee_state: Self, transferred_value: u128) {
        self.debug_buffer = callee_state.debug_buffer;
        self.events = callee_state.events;
        self.accounts = callee_state.accounts;
        self.accounts[self.caller_account].value -= transferred_value;
    }

    /// Access the contract that is currently being executed.
    fn contract(&mut self) -> &mut Contract {
        self.accounts[self.account].contract.as_mut().unwrap()
    }

    /// Call an exported function under the account found at index `callee`.
    ///
    /// Returns `None` if the account has no contract.
    fn call(
        &mut self,
        export: &str,
        callee: usize,
        input: Vec<u8>,
        value: u128,
    ) -> Option<Result<Store<Runtime>, Error>> {
        println!(
            "{export}: account={} input={} value={value}",
            hex::encode(self.accounts[callee].address),
            hex::encode(&input)
        );

        self.accounts[callee]
            .contract
            .as_ref()?
            .execute(export, self.new_context(callee, input, value))
            .map_err(|(err, debug_buffer)| {
                self.debug_buffer = debug_buffer;
                err
            })
            .into()
    }

    /// Add a new contract account and call its "deploy" function accordingly.
    ///
    /// Returns `None` if there is no contract corresponding to the given `code_hash`.
    fn deploy(
        &mut self,
        value: u128,
        salt: &[u8],
        input: Vec<u8>,
    ) -> Option<Result<Store<Runtime>, Error>> {
        let account = self
            .blobs
            .iter()
            .find(|code| code.constructors.contains(&input[..4].to_vec()))
            .map(|code| Account::with_contract(salt, code))?;
        if self.accounts.contains(&account) {
            return Some(Err(Error::Trap(TrapCode::UnreachableCodeReached.into())));
        }
        self.accounts.push(account);
        self.call("deploy", self.accounts.len() - 1, input, value)
    }
}

fn read_len(mem: &[u8], ptr: u32) -> usize {
    u32::from_le_bytes(mem[ptr as usize..ptr as usize + 4].try_into().unwrap()) as usize
}

fn write_buf(mem: &mut [u8], ptr: u32, buf: &[u8]) {
    mem[ptr as usize..ptr as usize + buf.len()].copy_from_slice(buf);
}

fn read_buf(mem: &[u8], ptr: u32, len: u32) -> Vec<u8> {
    mem[ptr as usize..(ptr + len) as usize].to_vec()
}

fn read_value(mem: &[u8], ptr: u32) -> u128 {
    u128::from_le_bytes(read_buf(mem, ptr, 16).try_into().unwrap())
}

fn read_account(mem: &[u8], ptr: u32) -> Address {
    Address::try_from(&mem[ptr as usize..(ptr + 20) as usize]).unwrap()
}

fn read_hash(mem: &[u8], ptr: u32) -> Hash {
    Hash::try_from(&mem[ptr as usize..(ptr + 32) as usize]).unwrap()
}

/// Host functions mock the original implementation, refer to the [pallet docs][1] for more information.
///
/// [1]: https://docs.rs/pallet-contracts/latest/pallet_contracts/api_doc/index.html
#[wasm_host]
impl Runtime {
    #[seal(0)]
    fn input(dest_ptr: u32, len_ptr: u32) -> Result<(), Trap> {
        let data = vm.input.as_ref().expect("input was forwarded");
        assert!(read_len(mem, len_ptr) >= data.len());
        println!("seal_input: {}, len: {:?} data len: {}", hex::encode(data), read_len(mem, len_ptr), data.len());

        write_buf(mem, dest_ptr, data);
        write_buf(mem, len_ptr, &(data.len() as u32).to_le_bytes());

        Ok(())
    }

    #[env]
    fn _evm_codecopy(mem_offset: u32, code_offset: u32, lenght: u32) -> Result<(), Trap> {
        let data = vm.input.as_ref().expect("input was forwarded");

        println!("_evm_codecopy: {}, len: {:?}", hex::encode(&data[code_offset as usize..code_offset as usize + lenght as usize]), lenght);

        write_buf(mem, mem_offset, data);

        Ok(())
    }

    #[env]
    fn _evm_codesize(dest: u32) -> Result<(), Trap> {
        let data = vm.input.as_ref().expect("input was forwarded");

        write_buf(mem, dest, &(data.len() as u32).to_le_bytes());

        Ok(())
    }


    #[seal(0)]
    fn seal_return(flags: u32, data_ptr: u32, data_len: u32) -> Result<(), Trap> {
        let output = read_buf(mem, data_ptr, data_len);
        println!("seal_return: {flags} {}", hex::encode(&output));
        Err(HostReturn::Data(flags, output).into())
    }



    #[env]
    fn _evm_sload(slot: u32, dest: u32) -> Result<(), Trap>{
        let key = StorageKey::try_from(read_buf(mem, slot, 32))
            .expect("storage key size must be 32 bytes");
        println!("Keys: {:?}", key);
        println!("Storages: {:?}", vm.contract().storage);
        let default_value = vec![0;32];
        let value = vm.contract().storage.get(&key).unwrap_or(&default_value);

        println!("_evm_sload: {}={:x?}", hex::encode(key), value);

        write_buf(mem, dest, value);

        Ok(())
    }

    #[env]
    fn _evm_sstore(
        slot: u32,
        value: u32,
    ) -> Result<(), Trap> {
        let key = StorageKey::try_from(read_buf(mem, slot, 32))
            .expect("storage key size must be 32 bytes");
        let value = mem[value as usize..(value + 32) as usize].to_vec();

        println!("_evm_sstore: {}={}, slot: {:?}", hex::encode(key), hex::encode(&value), slot);

        if value.as_slice() == &[0;32] {
            vm.contract().storage.remove(&key);
        } else {
            vm.contract().storage.insert(key, value);
        }

        Ok(())
    }

    #[env]
    fn _evm_return(data_ptr: u32, data_len: u32) -> Result<(), Trap> {
        let output = read_buf(mem, data_ptr, data_len);
        println!("_evm_return: {:?}, mem: {:?}, len: {}", output, data_ptr, data_len);

        Err(HostReturn::Data(0, output).into())
    }

    #[env]
    fn _evm_revert(error_ptr: u32, error_length: u32) -> Result<(), Trap> {
        let output = read_buf(mem, error_ptr, error_length);
        println!("_evm_revert: {:?}, mem: {:?}, len: {}", output, error_ptr, error_length);
        Err(HostReturn::Data(1, output).into())
    }

    #[seal(0)]
    fn value_transferred(dest_ptr: u32, out_len_ptr: u32) -> Result<(), Trap> {
        let value = vm.transferred_value.to_le_bytes();
        // assert!(read_len(mem, out_len_ptr) >= value.len());
        println!("seal_value_transferred: {}", vm.transferred_value);

        write_buf(mem, dest_ptr, &value);
        write_buf(mem, out_len_ptr, &(value.len() as u32).to_le_bytes());

        Ok(())
    }

    #[seal(0)]
    fn debug_message(data_ptr: u32, len: u32) -> Result<u32, Trap> {
        let buf = read_buf(mem, data_ptr, len);
        let msg = std::str::from_utf8(&buf).expect("seal_debug_message: Invalid UFT8");
        println!("seal_debug_message: {msg}");
        vm.debug_buffer.push_str(msg);

        Ok(0)
    }

    #[seal(1)]
    fn get_storage(
        key_ptr: u32,
        key_len: u32,
        out_ptr: u32,
        out_len_ptr: u32,
    ) -> Result<u32, Trap> {
        let key = StorageKey::try_from(read_buf(mem, key_ptr, key_len))
            .expect("storage key size must be 32 bytes");
        let value = match vm.contract().storage.get(&key) {
            Some(value) => value,
            _ => return Ok(3), // In pallet-contracts, ReturnCode::KeyNotFound == 3
        };
        println!("get_storage: {}={}", hex::encode(key), hex::encode(value));

        write_buf(mem, out_ptr, value);
        write_buf(mem, out_len_ptr, &(value.len() as u32).to_le_bytes());

        Ok(0)
    }

    #[seal(2)]
    fn set_storage(
        key_ptr: u32,
        key_len: u32,
        value_ptr: u32,
        value_len: u32,
    ) -> Result<u32, Trap> {
        let key = StorageKey::try_from(read_buf(mem, key_ptr, key_len))
            .expect("storage key size must be 32 bytes");
        let value = mem[value_ptr as usize..(value_ptr + value_len) as usize].to_vec();
        println!("set_storage key len, value len: {} {}", key_len, value_len);
        println!("set_storage: {}={}", hex::encode(key), hex::encode(&value));

        match vm.contract().storage.insert(key, value) {
            Some(value) => Ok(value.len() as u32),
            _ => Ok(u32::MAX), // In pallets contract, u32::MAX is the "none sentinel"
        }
    }

    #[seal(1)]
    fn clear_storage(key_ptr: u32, key_len: u32) -> Result<u32, Trap> {
        let key = StorageKey::try_from(read_buf(mem, key_ptr, key_len))
            .expect("storage key size must be 32 bytes");
        println!("clear_storage: {}", hex::encode(key));

        match vm.contract().storage.remove(&key) {
            Some(value) => Ok(value.len() as u32),
            _ => Ok(u32::MAX), // In pallets contract, u32::MAX is the "none sentinel"
        }
    }

    #[env]
    fn _evm_keccak256(input_ptr: u32, input_len: u32, output_ptr: u32) -> Result<(), Trap> {
        let mut hasher = Keccak::v256();
        hasher.update(&read_buf(mem, input_ptr, input_len));
        hasher.finalize(&mut mem[output_ptr as usize..(output_ptr + 32) as usize]);
        Ok(())
    }


    #[seal(0)]
    fn hash_keccak_256(input_ptr: u32, input_len: u32, output_ptr: u32) -> Result<(), Trap> {
        let mut hasher = Keccak::v256();
        hasher.update(&read_buf(mem, input_ptr, input_len));
        hasher.finalize(&mut mem[output_ptr as usize..(output_ptr + 32) as usize]);
        Ok(())
    }

    #[seal(0)]
    fn hash_sha2_256(input_ptr: u32, input_len: u32, output_ptr: u32) -> Result<(), Trap> {
        let mut hasher = Sha256::new();
        hasher.update(read_buf(mem, input_ptr, input_len));
        write_buf(mem, output_ptr, &hasher.finalize());
        Ok(())
    }

    #[seal(0)]
    fn hash_blake2_128(input_ptr: u32, input_len: u32, output_ptr: u32) -> Result<(), Trap> {
        let data = read_buf(mem, input_ptr, input_len);
        write_buf(mem, output_ptr, blake2b(16, &[], &data).as_bytes());
        Ok(())
    }

    #[seal(0)]
    fn hash_blake2_256(input_ptr: u32, input_len: u32, output_ptr: u32) -> Result<(), Trap> {
        let data = read_buf(mem, input_ptr, input_len);
        write_buf(mem, output_ptr, blake2b(32, &[], &data).as_bytes());
        Ok(())
    }

    #[env]
    fn _evm_call(
        gas: u64,
        address: u32,
        value: u32,
        input_offset: u32,
        input_length: u32,
        return_offset: u32,
        return_length: u32,
        dest: u32
    ) -> Result<(), Trap> {
        let input = read_buf(mem, input_offset, input_length);
        let value = read_value(mem, value);
        let address = read_account(mem, address);

        println!("_evm_call");

        let callee = if let Some(callee) = vm
            .accounts
            .iter()
            .enumerate()
            .find(|(_, account)| account.address == address)
            .map(|(index, _)| index) {
            callee
        } else {
            return Ok(());
        };
        assert!(value <= vm.accounts[vm.account].value, "TransferFailed");
        let ((ret, data), state) = match vm.call("call", callee, input, value) {
            Some(Ok(state)) => ((state.data().output.as_data()), state),
            _ => panic!("Failed while call contract"),
        };

        if return_length != u32::MAX {
            assert!(read_len(mem, return_length) >= data.len());
            write_buf(mem, return_offset, &data);
            write_buf(mem, return_length, &(data.len() as u32).to_le_bytes());
        }

        if ret == 0 {
            let data = state.into_data();
            vm.accept_state(data, value);
            mem[dest as usize] = true as u8;
            //set dest to true
        }
        println!("Evm call ok {}", ret);
        Ok(())
    }

    #[env]
    fn _evm_delegatecall(
        gas: u64,
        address: u32,
        input_offset: u32,
        input_length: u32,
        return_offset: u32,
        return_length: u32,
        dest: u32
    ) -> Result<(), Trap> {
        let input = read_buf(mem, input_offset, input_length);
        let address = read_account(mem, address);

        let callee = vm
            .accounts
            .iter()
            .enumerate()
            .find(|(_, account)| account.address == address)
            .map(|(index, _)| index).expect("Contract not found");

        let ((ret, data), state) = match vm.call("call", callee, input, 0) {
            Some(Ok(state)) => ((state.data().output.as_data()), state),
            _ => panic!("Failed while call contract"),
        };

        if return_length != u32::MAX {
            assert!(read_len(mem, return_length) >= data.len());
            write_buf(mem, return_offset, &data);
            write_buf(mem, return_length, &(data.len() as u32).to_le_bytes());
        }

        if ret == 0 {
            let data = state.into_data();
            vm.accept_state(data, value);
            mem[dest as usize] = true as u8;
            //set dest to true
        }

        Ok(())
    }

    #[seal(1)]
    fn seal_call(
        flags: u32,
        callee_ptr: u32,
        _gas: u64,
        value_ptr: u32,
        input_ptr: u32,
        input_len: u32,
        output_ptr: u32,
        output_len_ptr: u32,
    ) -> Result<u32, Trap> {
        assert!(flags <= 0b1111);

        let input = if CallFlags::ForwardInput.set(flags) {
            if vm.input.is_none() {
                return Ok(1);
            }
            vm.input.take().unwrap()
        } else if CallFlags::CloneInput.set(flags) {
            if vm.input.is_none() {
                return Ok(2);
            }
            vm.input.as_ref().unwrap().clone()
        } else {
            read_buf(mem, input_ptr, input_len)
        };
        let value = read_value(mem, value_ptr);
        let callee_address = read_account(mem, callee_ptr);


        let callee = match vm
            .accounts
            .iter()
            .enumerate()
            .find(|(_, account)| account.address == callee_address)
            .map(|(index, _)| index)
        {
            Some(index) => index,
            None => return Ok(8), // ReturnCode::NotCallable
        };

        if vm.called_accounts.contains(&callee) && !CallFlags::AllowReentry.set(flags) {
            return Ok(3);
        }

        if value > vm.accounts[vm.account].value {
            return Ok(5); // ReturnCode::TransferFailed
        }

        let ((ret, data), state) = match vm.call("call", callee, input, value) {
            Some(Ok(state)) => ((state.data().output.as_data()), state),
            Some(Err(_)) => return Ok(4), // ReturnCode::CalleeTrapped
            None => return Ok(8),
        };

        if CallFlags::TailCall.set(flags) {
            return Err(HostReturn::Data(ret, data).into());
        }

        if output_len_ptr != u32::MAX {
            assert!(read_len(mem, output_len_ptr) >= data.len());
            write_buf(mem, output_ptr, &data);
            write_buf(mem, output_len_ptr, &(data.len() as u32).to_le_bytes());
        }

        if ret == 0 {
            vm.accept_state(state.into_data(), value);
        }
        Ok(ret)
    }

    #[seal(0)]
    fn instantiation_nonce() -> Result<u64, Trap> {
        Ok(vm.accounts.len() as u64)
    }

    #[seal(0)]
    fn minimum_balance(out_ptr: u32, out_len_ptr: u32) -> Result<(), Trap> {
        assert!(read_len(mem, out_len_ptr) >= 16);
        write_buf(mem, out_ptr, &500u128.to_le_bytes());
        Ok(())
    }

    #[env]
    fn _evm_create2(
        value: u32,
        constructor_offset: u32,
        constructor_length: u32,
        salt: u32,
        dest: u32,
    ) -> Result<(), Trap> {
        let input = read_buf(mem, constructor_offset, constructor_length);
        let salt = read_buf(mem, salt, 32);
        let value = read_value(mem, value);
        let mut address = [0;20];

        println!("_evm_create2");
        assert!(value <= vm.accounts[vm.account].value, "TransferFailed");

        let state = match vm.deploy(value, &salt, input) {
            Some(Ok(state)) => state,
            _ => return Ok(()),
        };

        if state.data().output.as_data().0 == 0 {
            address = state.data().accounts.last().unwrap().address;
            write_buf(mem, dest, &address);
            vm.accept_state(state.into_data(), value);
        }

        println!("Create2 address: {:?}", address);

        Ok(())
    }

    #[env]
    fn _evm_create(
        value: u32,
        bytecode_offset: u32,
        bytecode_length: u32,
        dest: u32,
    ) -> Result<(), Trap> {
        let input = read_buf(mem, bytecode_offset, bytecode_length);
        let value = read_value(mem, value);
        let mut address = [0;20];

        println!("_evm_create");
        assert!(value <= vm.accounts[vm.account].value, "TransferFailed");

        let state = vm.deploy(value, &[], input).expect("CodeNotFound").expect("CalleeTrapped");

        if state.data().output.as_data().0 == 0 {
            address = state.data().accounts.last().unwrap().address;
            write_buf(mem, dest, &address);
            vm.accept_state(state.into_data(), value);
        }

        Ok(())
    }


    #[seal(0)]
    fn transfer(
        account_ptr: u32,
        account_len: u32,
        value_ptr: u32,
        value_len: u32,
    ) -> Result<u32, Trap> {
        assert_eq!(account_len, 32);
        assert_eq!(value_len, 16);

        let value = read_value(mem, value_ptr);
        if value > vm.accounts[vm.account].value {
            return Ok(5); // ReturnCode::TransferFailed
        }

        let account = read_account(mem, account_ptr);
        if let Some(to) = vm.accounts.iter_mut().find(|c| c.address == account) {
            to.value += value;
            vm.accounts[vm.account].value -= value;
            return Ok(0);
        }

        Ok(5)
    }

    #[seal(0)]
    fn address(out_ptr: u32, out_len_ptr: u32) -> Result<(), Trap> {
        let address = vm.accounts[vm.account].address;
        let out_len = read_len(mem, out_len_ptr);
        assert!(out_len >= address.len());

        write_buf(mem, out_ptr, &address);
        write_buf(mem, out_len_ptr, &(address.len() as u32).to_le_bytes());

        Ok(())
    }

    #[env]
    fn _evm_address(dest: u32) -> Result<(), Trap> {
        let address = vm.accounts[vm.account].address;

        write_buf(mem, dest, &address);

        Ok(())
    }

    #[seal(0)]
    fn caller(out_ptr: u32, out_len_ptr: u32) -> Result<(), Trap> {
        let out_len = read_len(mem, out_len_ptr);
        let address = vm.accounts[vm.caller_account].address;
        assert!(out_len >= address.len());

        write_buf(mem, out_ptr, &address);
        write_buf(mem, out_len_ptr, &(address.len() as u32).to_le_bytes());

        Ok(())
    }

    #[env]
    fn _evm_gas(out_ptr: u32) -> Result<(), Trap> {
        let gas_left = (1000 as u128).to_le_bytes();

        println!("_evm_gas: {:?}", gas_left);

        write_buf(mem, out_ptr as u32, &gas_left);

        Ok(())
    }

    #[env]
    fn _evm_caller(out_ptr: u32) -> Result<(), Trap> {
        let address = vm.accounts[vm.account].address;
        println!("_evm_caller: {:?}", address);
        write_buf(mem, out_ptr as u32, &address);

        Ok(())
    }

    #[env]
    fn _evm_callvalue(out_ptr: u32) -> Result<(), Trap> {
        let value = (0 as u128).to_le_bytes();

        println!("_evm_callvalue: {:?}", value);
        write_buf(mem, out_ptr as u32, &value);

        Ok(())
    }

    #[seal(0)]
    fn balance(out_ptr: u32, out_len_ptr: u32) -> Result<(), Trap> {
        let balance = vm.accounts[vm.account].value.to_le_bytes();
        let out_len = read_len(mem, out_len_ptr);
        assert!(out_len >= balance.len());

        write_buf(mem, out_ptr, &balance);
        write_buf(mem, out_len_ptr, &(balance.len() as u32).to_le_bytes());

        Ok(())
    }

    #[env]
    fn _evm_balance(address: u32, dest: u32) -> Result<(), Trap> {
        let target_address = read_buf(mem, address, 20);

        let balance = vm.accounts.iter().find(|acc| acc.address.as_slice().eq(target_address.as_slice()))
            .map(|acc| acc.value.to_le_bytes()).unwrap();

        write_buf(mem, dest, &balance);

        Ok(())
    }



    #[seal(0)]
    fn block_number(out_ptr: u32, out_len_ptr: u32) -> Result<(), Trap> {
        let block = 950_119_597u32.to_le_bytes();
        let out_len = read_len(mem, out_len_ptr);
        assert!(out_len >= block.len());

        write_buf(mem, out_ptr, &block);
        write_buf(mem, out_len_ptr, &(block.len() as u32).to_le_bytes());

        Ok(())
    }

    #[seal(0)]
    fn now(out_ptr: u32, out_len_ptr: u32) -> Result<(), Trap> {
        let now = 1594035638000u64.to_le_bytes();
        let out_len = read_len(mem, out_len_ptr);
        assert!(out_len >= now.len());

        write_buf(mem, out_ptr, &now);
        write_buf(mem, out_len_ptr, &(now.len() as u32).to_le_bytes());

        Ok(())
    }

    #[seal(0)]
    fn gas_left(out_ptr: u32, out_len_ptr: u32) -> Result<(), Trap> {
        let gas = 2_224_097_461u64.to_le_bytes();
        let out_len = read_len(mem, out_len_ptr);
        assert!(out_len >= gas.len());

        write_buf(mem, out_ptr, &gas);
        write_buf(mem, out_len_ptr, &(gas.len() as u32).to_le_bytes());

        Ok(())
    }

    #[seal(0)]
    fn weight_to_fee(gas: u64, out_ptr: u32, out_len_ptr: u32) -> Result<(), Trap> {
        let price = (59_541_253_813_967 * gas as u128).to_le_bytes();
        let out_len = read_len(mem, out_len_ptr);
        assert!(out_len >= price.len());

        write_buf(mem, out_ptr, &price);
        write_buf(mem, out_len_ptr, &(price.len() as u32).to_le_bytes());

        Ok(())
    }

    #[env]
    fn _evm_gasprice(out_ptr: u32) -> Result<(), Trap> {
        let price = (59_541_253_813_970 as u128).to_le_bytes();

        write_buf(mem, out_ptr as u32, &price);

        Ok(())
    }

    #[env]
    fn _evm_timestamp(out_ptr: u32) -> Result<(), Trap> {
        let timestamp = (1594035638 as u128).to_le_bytes();

        write_buf(mem, out_ptr as u32, &timestamp);

        Ok(())
    }

    #[env]
    fn _evm_number(out_ptr: u32) -> Result<(), Trap> {
        let block_number = (950_119_597 as u128).to_le_bytes();
        write_buf(mem, out_ptr as u32, &block_number);

        Ok(())
    }

    #[seal(1)]
    fn terminate(beneficiary_ptr: u32) -> Result<(), Trap> {
        let free = vm.accounts.remove(vm.account).value;
        let address = read_account(mem, beneficiary_ptr);
        println!("seal_terminate: {} gets {free}", hex::encode(address));

        if let Some(to) = vm.accounts.iter_mut().find(|a| a.address == address) {
            to.value += free;
        }

        Err(HostReturn::Terminate.into())
    }

    #[env]
    fn _evm_log0(
        data_offset: u32,
        data_length: u32,
    ) -> Result<(), Trap> {

        let data = read_buf(mem, data_offset, data_length);

        println!(
            "_evm_log0 data: {}",
            hex::encode(&data),
        );

        vm.events.push(Event { data, topics: vec![] });

        Ok(())
    }

    #[env]
    fn _evm_log1(
        data_offset: u32,
        data_length: u32,
        topic0: u32,
    ) -> Result<(), Trap> {

        let data = read_buf(mem, data_offset, data_length);
        let topic = Hash::decode(&mut read_buf(mem, topic0, 32).as_slice()).unwrap();

        println!(
            "_evm_log1 data: {:x?} topic: {:?}",
            hex::encode(&data),
            topic
        );
        vm.events.push(Event { data, topics: vec![topic] });

        println!("Events: {:?}", vm.events.len());
        Ok(())
    }

    #[env]
    fn _evm_log2(
        data_offset: u32,
        data_length: u32,
        topic0: u32,
        topic1: u32,
    ) -> Result<(), Trap> {
        let data = read_buf(mem, data_offset, data_length);
        let topic0 = Hash::decode(&mut read_buf(mem, topic0, 32).as_slice()).unwrap();
        let topic1 = Hash::decode(&mut read_buf(mem, topic1, 32).as_slice()).unwrap();

        println!(
            "_evm_log2 data: {:x?} topic0: {:x?}, topic1: {:x?}",
            hex::encode(&data),
            topic0,
            topic1,
        );
        vm.events.push(Event { data, topics: vec![topic0, topic1] });

        println!("Events: {:?}", vm.events.len());

        Ok(())
    }

    #[env]
    fn _evm_log3(
        data_offset: u32,
        data_length: u32,
        topic0: u32,
        topic1: u32,
        topic2: u32,
    ) -> Result<(), Trap> {
        let data = read_buf(mem, data_offset, data_length);
        let topic0 = Hash::decode(&mut read_buf(mem, topic0, 32).as_slice()).unwrap();
        let topic1 = Hash::decode(&mut read_buf(mem, topic1, 32).as_slice()).unwrap();
        let topic2 = Hash::decode(&mut read_buf(mem, topic2, 32).as_slice()).unwrap();

        println!(
            "_evm_log3 data: {:x?} topic0: {:?}, topic1: {:?}, topic2: {:?}",
            hex::encode(&data),
            topic0,
            topic1,
            topic2,
        );
        vm.events.push(Event { data, topics: vec![topic0, topic1, topic2] });

        println!("Events: {:?}", vm.events.len());

        Ok(())
    }

    #[env]
    fn _evm_log4(
        data_offset: u32,
        data_length: u32,
        topic0: u32,
        topic1: u32,
        topic2: u32,
        topic3: u32,
    ) -> Result<(), Trap> {
        let data = read_buf(mem, data_offset, data_length);
        let topic0 = Hash::decode(&mut read_buf(mem, topic0, 32).as_slice()).unwrap();
        let topic1 = Hash::decode(&mut read_buf(mem, topic1, 32).as_slice()).unwrap();
        let topic2 = Hash::decode(&mut read_buf(mem, topic2, 32).as_slice()).unwrap();
        let topic3 = Hash::decode(&mut read_buf(mem, topic3, 32).as_slice()).unwrap();

        println!(
            "_evm_log4 data: {:x?} topic0: {:?}, topic1: {:?}, topic2: {:?}, topic3: {:?}",
            hex::encode(&data),
            topic0,
            topic1,
            topic2,
            topic3,
        );
        vm.events.push(Event { data, topics: vec![topic0, topic1, topic2, topic3] });

        println!("Events: {:?}", vm.events.len());

        Ok(())
    }

    #[seal(0)]
    fn deposit_event(
        topics_ptr: u32,
        topics_len: u32,
        data_ptr: u32,
        data_len: u32,
    ) -> Result<(), Trap> {
        let data = read_buf(mem, data_ptr, data_len);
        let topics = if topics_len > 0 {
            <Vec<Hash>>::decode(&mut &read_buf(mem, topics_ptr, topics_len)[..]).unwrap()
        } else {
            vec![]
        };

        println!(
            "seal_deposit_event data: {} topics: {:?}",
            hex::encode(&data),
            topics.iter().map(hex::encode).collect::<Vec<_>>()
        );

        vm.events.push(Event { data, topics });

        Ok(())
    }

    /// Mock chain extension with ID 123 that writes the reversed input to the output buf.
    /// Returns the sum of the input data.
    #[seal(0)]
    fn call_chain_extension(
        id: u32,
        input_ptr: u32,
        input_len: u32,
        output_ptr: u32,
        output_len_ptr: u32,
    ) -> Result<u32, Trap> {
        assert_eq!(id, 123, "unkown chain extension");
        assert!(read_len(mem, output_len_ptr) == 16384 && input_len <= 16384);

        let mut data = read_buf(mem, input_ptr, input_len);
        data.reverse();

        write_buf(mem, output_ptr, &data);
        write_buf(mem, output_len_ptr, &(data.len() as u32).to_le_bytes());

        Ok(data.iter().map(|i| *i as u32).sum())
    }

    #[seal(0)]
    fn is_contract(input_ptr: u32) -> Result<u32, Trap> {
        let address = read_account(mem, input_ptr);
        Ok(vm
            .accounts
            .iter()
            .any(|account| account.contract.is_some() && account.address == address)
            .into())
    }

    #[seal(0)]
    fn set_code_hash(code_hash_ptr: u32) -> Result<u32, Trap> {
        let hash = read_hash(mem, code_hash_ptr);
        if let Some(code) = vm.blobs.iter().find(|code| code.hash == hash) {
            vm.accounts[vm.account].contract.as_mut().unwrap().code = code.clone();
            return Ok(0);
        }
        Ok(7) // ReturnCode::CodeNoteFound
    }


}

/// Provides a mock implementation of substrates [contracts pallet][1]
///
/// [1]: https://docs.rs/pallet-contracts/latest/pallet_contracts/index.html
pub struct MockWasm(Store<Runtime>);

impl MockWasm {
    fn invoke(&mut self, export: &str, input: Vec<u8>) -> Result<(), Error> {
        let callee = self.0.data().account;
        let value = self.0.data().transferred_value;
        let runtime = self.0.data_mut();

        runtime.debug_buffer.clear();
        runtime.events.clear();
        runtime.called_accounts.clear();
        self.0 = runtime.call(export, callee, input, value).unwrap()?;
        println!("Account after invoke: {:?}", self.0.data().accounts);
        self.0.data_mut().transferred_value = 0;

        Ok(())
    }

    /// Specify the caller account index for the next function or constructor call.
    pub fn set_account(&mut self, index: usize) {
        self.0.data_mut().account = index;
    }

    /// Specify the balance for the next function or constructor call.
    pub fn set_transferred_value(&mut self, amount: u128) {
        self.0.data_mut().transferred_value = amount;
    }

    /// Get the balance of the given `account`.
    pub fn balance(&self, account: usize) -> u128 {
        self.0.data().accounts[account].value
    }

    /// Get the address of the calling account.
    pub fn caller(&self) -> Address {
        self.0.data().accounts[self.0.data().caller_account].address
    }

    /// Get the output of the last function or constructor call.
    pub fn output(&self) -> Vec<u8> {
        if let HostReturn::Data(_, data) = &self.0.data().output {
            return data.to_vec();
        }
        vec![]
    }

    /// Get the debug buffer contents of the last function or constructor call.
    pub fn debug_buffer(&self) -> String {
        self.0.data().debug_buffer.clone()
    }

    /// Get the emitted events of the last function or constructor call.
    pub fn events(&self) -> Vec<Event> {
        self.0.data().events.clone()
    }

    /// Get a list of all deployed contracts.
    pub fn contracts(&self) -> Vec<&Contract> {
        self.0
            .data()
            .accounts
            .iter()
            .map(|a| a.contract.as_ref().unwrap())
            .collect()
    }

    /// Read the storage of the account that was (or is about to be) called.
    pub fn storage(&self) -> &HashMap<StorageKey, Vec<u8>> {
        &self.0.data().accounts[self.0.data().account]
            .contract
            .as_ref()
            .unwrap()
            .storage
    }

    /// Get the selector of the given `function_name` on the given `contract` index.
    pub fn selector(&self, contract: usize, function_name: &str) -> &[u8] {
        &self.0.data().blobs[contract].messages[function_name]
    }

    /// Execute the constructor `index` with the given input `args`.
    pub fn constructor(&mut self, index: usize, mut args: Vec<u8>) {
        let mut input = self.0.data().blobs[self.0.data().account].constructors[index].clone();
        input.append(&mut args);
        self.raw_constructor(input);
    }

    /// Get a list of all uploaded cotracts
    pub fn blobs(&self) -> Vec<WasmCode> {
        self.0.data().blobs.clone()
    }

    /// Call the "deploy" function with the given `input`.
    ///
    /// `input` must contain the selector fo the constructor.
    pub fn raw_constructor(&mut self, input: Vec<u8>) {
        self.0.data_mut().transferred_value = 20000;
        self.invoke("deploy", input).unwrap();
    }

    /// Call the contract function `name` with the given input `args`.
    /// Panics if the contract traps or reverts.
    pub fn function(&mut self, name: &str, mut args: Vec<u8>) {
        let mut input = self.0.data().blobs[self.0.data().account].messages[name].clone();
        input.append(&mut args);
        self.raw_function(input);
    }

    /// Expect the contract function `name` with the given input `args` to trap or revert.
    ///
    /// Only traps caused by an `unreachable` instruction are allowed. Other traps will panic instead.
    pub fn function_expect_failure(&mut self, name: &str, mut args: Vec<u8>) {
        let mut input = self.0.data().blobs[self.0.data().account].messages[name].clone();
        input.append(&mut args);
        self.raw_function_failure(input);
    }

    /// Call the "deploy" function with the given `input`.
    ///
    /// `input` must contain the selector fo the constructor.
    pub fn raw_function(&mut self, input: Vec<u8>) {
        self.invoke("call", input).unwrap();
        if let HostReturn::Data(flags, _) = self.0.data().output {
            assert!(flags == 0)
        }
    }

    fn raw_failure(&mut self, export: &str, input: Vec<u8>) {
        println!("Output: {:?}", self.0.data().output);
        match self.invoke(export, input) {
            Err(wasmi::Error::Trap(trap)) => match trap.trap_code() {
                Some(TrapCode::UnreachableCodeReached) => (),
                _ => panic!("trap: {trap:?}"),
            },
            Err(err) => panic!("unexpected error: {err:?}"),
            Ok(_) => match self.0.data().output {
                HostReturn::Data(flags, _) if flags == 1 => (),
                _ => panic!("unexpected return from main"),
            },
        }
    }

    /// Call the "call" function with the given input and expect the contract to trap.
    ///
    /// `input` must contain the desired function selector.
    ///
    /// Only traps caused by an `unreachable` instruction are allowed. Other traps will panic instead.
    pub fn raw_function_failure(&mut self, input: Vec<u8>) {
        self.raw_failure("call", input);
    }

    /// Call the "deploy" function with the given input and expect the contract to trap.
    ///
    /// `input` must contain the desired function selector.
    ///
    /// Only traps caused by an `unreachable` instruction are allowed. Other traps will panic instead.
    pub fn raw_constructor_failure(&mut self, input: Vec<u8>) {
        self.raw_failure("deploy", input);
    }

    pub fn heap_verify(&mut self) {
        let mem = self.0.data().memory.unwrap().data(&mut self.0);
        let memsize = mem.len();
        println!("memory size:{memsize}");
        let mut buf = Vec::new();
        buf.resize(memsize, 0);

        let mut current_elem = 0x10000;
        let mut last_elem = 0u32;

        let read_u32 = |ptr| u32::from_le_bytes(mem[ptr..ptr + 4].try_into().unwrap());

        loop {
            let next: u32 = read_u32(current_elem);
            let prev: u32 = read_u32(current_elem + 4);
            let length: u32 = read_u32(current_elem + 8);
            let allocated: u32 = read_u32(current_elem + 12);

            println!("next:{next:08x} prev:{prev:08x} length:{length} allocated:{allocated}");

            let buf = read_buf(mem, current_elem as u32 + 16, length);

            if allocated == 0 {
                println!("{:08x} {} not allocated", current_elem + 16, length);
            } else {
                println!("{:08x} {} allocated", current_elem + 16, length);

                assert_eq!(allocated & 0xffff, 1);

                for offset in (0..buf.len()).step_by(16) {
                    let mut hex = "\t".to_string();
                    let mut chars = "\t".to_string();
                    for i in 0..16 {
                        if offset + i >= buf.len() {
                            break;
                        }
                        let b = buf[offset + i];
                        write!(hex, " {b:02x}").unwrap();
                        if b.is_ascii() && !b.is_ascii_control() {
                            write!(chars, "  {}", b as char).unwrap();
                        } else {
                            chars.push_str("   ");
                        }
                    }
                    println!("{hex}\n{chars}");
                }
            }

            assert_eq!(last_elem, prev);

            if next == 0 {
                break;
            }

            last_elem = current_elem as u32;
            current_elem = next as usize;
        }
    }
}

/// Build all contracts foud in `src` and set up a mock runtime.
///
/// The mock runtime will contain a contract account for each contract in `src`:
/// * Each account will have a balance of 20'000
/// * However, constructors are _not_ called, therefor the storage will not be initialized
pub fn build_solidity_for_fluentbase(src: &str) -> MockWasm {
    build_solidity_with_options(src, false, true)
}

/// A variant of `MockSubstrate::uild_solidity()` with the ability to specify compiler options:
/// * log_ret: enable logging of host function return codes
/// * log_err: enable logging of runtime errors
pub fn build_solidity_with_options(src: &str, log_ret: bool, log_err: bool) -> MockWasm {
    let blobs = build_wasm(src, log_ret, log_err, Target::FLUENTBASE)
        .iter()
        .map(|(code, abi)| WasmCode::new(abi, code))
        .collect();
    println!("Wasm code: {:?}", blobs);

    MockWasm(Store::new(&Engine::default(), Runtime::new(blobs)))
}

pub fn build_wasm(src: &str, log_ret: bool, log_err: bool, target: Target) -> Vec<(Vec<u8>, String)> {
    let tmp_file = OsStr::new("test.sol");
    let mut cache = FileResolver::new();
    cache.set_file_contents(tmp_file.to_str().unwrap(), src.to_string());
    let opt = inkwell::OptimizationLevel::Default;
    let (wasm, ns) = compile(
        tmp_file,
        &mut cache,
        opt,
        target,
        log_ret,
        log_err,
        true,
        vec!["unknown".to_string()],
        "0.0.1",
        #[cfg(feature = "wasm_opt")]
        Some(contract_build::OptimizationPasses::Z),
    );
    ns.print_diagnostics_in_plain(&cache, false);
    assert!(!wasm.is_empty());
    wasm
}

pub fn load_abi(s: &str) -> InkProject {
    println!("String: {}", s);
    let bundle = serde_json::from_str::<ContractMetadata>(s).unwrap();
    serde_json::from_value::<InkProject>(serde_json::to_value(bundle.abi).unwrap()).unwrap()
}
