// SPDX-License-Identifier: Apache-2.0

use crate::codegen::cfg::{HashTy, ReturnCode};
use crate::emit::binary::Binary;
use crate::emit::expression::expression;
use crate::emit::fluentbase::{log_return_code, FluentbaseTarget, SCRATCH_SIZE};
use crate::emit::storage::StorageSlot;
use crate::emit::{ContractArgs, TargetRuntime, Variable};
use crate::sema::ast;
use crate::sema::ast::{Function, Namespace, Type};
use crate::{codegen, emit_fluentbase_context};
use inkwell::types::{BasicType, BasicTypeEnum, IntType};
use inkwell::values::BasicValue;
use inkwell::values::AsValueRef;
use inkwell::values::{
    ArrayValue, BasicMetadataValueEnum, BasicValueEnum, FunctionValue, IntValue, PointerValue,
};
use inkwell::{AddressSpace, IntPredicate};
use solang_parser::pt::Loc;
use std::collections::HashMap;

impl<'a> TargetRuntime<'a> for FluentbaseTarget {
    fn set_storage_extfunc(
        &self,
        binary: &Binary,
        _function: FunctionValue,
        slot: PointerValue,
        dest: PointerValue,
        dest_ty: BasicTypeEnum,
    ) {
        emit_fluentbase_context!(binary);

        let dest_len = dest_ty
            .size_of()
            .unwrap()
            .const_cast(binary.context.i32_type(), false);

        let value = binary
            .builder
            .build_array_alloca(binary.context.i8_type(), binary.context.i32_type().const_int(32, false), "topic");
        call!(
            "__memcpy",
            &[
                value.into(),
                dest.into(),
                dest_len.into(),
            ]
        );

        let ret = seal_set_storage!(
            slot.into(),
            value.into()
        );

        log_return_code(binary, "seal_set_storage", ret);
    }

    fn get_storage_extfunc(
        &self,
        binary: &Binary<'a>,
        _function: FunctionValue,
        slot: PointerValue<'a>,
        ns: &ast::Namespace,
    ) -> PointerValue<'a> {
        emit_fluentbase_context!(binary);

        // This is the size of the external function struct
        let len = ns.address_length + 4;

        let ef = call!(
            "__malloc",
            &[binary
                .context
                .i32_type()
                .const_int(len as u64, false)
                .into()]
        )
        .try_as_basic_value()
        .left()
        .unwrap()
        .into_pointer_value();

        let scratch_len = binary.scratch_len.unwrap().as_pointer_value();
        binary.builder.build_store(
            scratch_len,
            binary.context.i64_type().const_int(len as u64, false),
        );

        let ret = call!(
            "_evm_sstore",
            &[
                slot.into(),
                ef.into(),
            ]
        )
        .try_as_basic_value()
        .left()
        .unwrap()
        .into_int_value();

        log_return_code(binary, "seal_get_storage: ", ret);

        // TODO: decide behaviour if not exist

        ef
    }

    fn set_storage_string(
        &self,
        binary: &Binary<'a>,
        function: FunctionValue<'a>,
        slot: PointerValue<'a>,
        dest: BasicValueEnum<'a>,
    ) {
        emit_fluentbase_context!(binary);

        let len = binary.vector_len(dest);
        let data = binary.vector_bytes(dest);

        let exists = binary
            .builder
            .build_int_compare(IntPredicate::NE, len, i32_zero!(), "exists");

        let delete_block = binary.context.append_basic_block(function, "delete_block");

        let set_block = binary.context.append_basic_block(function, "set_block");

        let done_storage = binary.context.append_basic_block(function, "done_storage");

        binary
            .builder
            .build_conditional_branch(exists, set_block, delete_block);

        binary.builder.position_at_end(set_block);

        let value = binary
            .builder
            .build_array_alloca(binary.context.i8_type(), binary.context.i32_type().const_int(32, false), "topic");
        call!(
            "__memcpy",
            &[
                value.into(),
                data.into(),
                len.into(),
            ]
        );

        let ret = seal_set_storage!(
            slot.into(),
            value.into()
        );


        log_return_code(binary, "seal_set_storage", ret);

        binary.builder.build_unconditional_branch(done_storage);

        binary.builder.position_at_end(delete_block);

        let value = binary
            .builder
            .build_array_alloca(binary.context.i8_type(), binary.context.i32_type().const_int(32, false), "topic");
        call!(
            "__memset",
            &[
                value.into(),
                binary.context.i8_type().const_int(0, false).into(),
                binary.context.i32_type().const_int(32, false).into(),
            ]
        );

        let ret = seal_set_storage!(
            slot.into(),
            value.into()
        );

        log_return_code(binary, "seal_clear_storage", ret);

        binary.builder.build_unconditional_branch(done_storage);

        binary.builder.position_at_end(done_storage);
    }

    /// Read from contract storage
    fn get_storage_int(
        &self,
        binary: &Binary<'a>,
        function: FunctionValue,
        slot: PointerValue<'a>,
        ty: IntType<'a>,
    ) -> IntValue<'a> {
        emit_fluentbase_context!(binary);

        let (scratch_buf, scratch_len) = scratch_buf!();
        let ty_len = ty.size_of().const_cast(binary.context.i32_type(), false);
        binary.builder.build_store(scratch_len, ty_len);

        let exists = seal_get_storage!(
            slot.into(),
            scratch_buf.into(),
        );

        log_return_code(binary, "seal_get_storage: ", exists);

        let exists = binary.builder.build_int_compare(
            IntPredicate::EQ,
            exists,
            i32_zero!(),
            "storage_exists",
        );

        let entry = binary.builder.get_insert_block().unwrap();
        let retrieve_block = binary.context.append_basic_block(function, "in_storage");
        let done_storage = binary.context.append_basic_block(function, "done_storage");

        binary
            .builder
            .build_conditional_branch(exists, retrieve_block, done_storage);

        binary.builder.position_at_end(retrieve_block);

        let loaded_int =
            binary
                .builder
                .build_load(ty, binary.scratch.unwrap().as_pointer_value(), "int");

        binary.builder.build_unconditional_branch(done_storage);

        binary.builder.position_at_end(done_storage);

        let res = binary.builder.build_phi(ty, "storage_res");

        res.add_incoming(&[(&loaded_int, retrieve_block), (&ty.const_zero(), entry)]);

        res.as_basic_value().into_int_value()
    }

    /// Read string from contract storage
    fn get_storage_string(
        &self,
        binary: &Binary<'a>,
        function: FunctionValue,
        slot: PointerValue<'a>,
    ) -> PointerValue<'a> {
        emit_fluentbase_context!(binary);

        let (scratch_buf, scratch_len) = scratch_buf!();

        binary
            .builder
            .build_store(scratch_len, i32_const!(SCRATCH_SIZE as u64));

        let exists = seal_get_storage!(
            slot.into(),
            scratch_buf.into(),
        );

        log_return_code(binary, "seal_get_storage: ", exists);

        let exists = binary.builder.build_int_compare(
            IntPredicate::EQ,
            exists,
            i32_zero!(),
            "storage_exists",
        );

        let ty = binary
            .module
            .get_struct_type("struct.vector")
            .unwrap()
            .ptr_type(AddressSpace::default());

        let entry = binary.builder.get_insert_block().unwrap();

        let retrieve_block = binary
            .context
            .append_basic_block(function, "retrieve_block");

        let done_storage = binary.context.append_basic_block(function, "done_storage");

        binary
            .builder
            .build_conditional_branch(exists, retrieve_block, done_storage);

        binary.builder.position_at_end(retrieve_block);

        let length =
            binary
                .builder
                .build_load(binary.context.i32_type(), scratch_len, "string_len");

        let loaded_string = call!(
            "vector_new",
            &[length.into(), i32_const!(1).into(), scratch_buf.into()]
        )
        .try_as_basic_value()
        .left()
        .unwrap()
        .into_pointer_value();

        binary.builder.build_unconditional_branch(done_storage);

        binary.builder.position_at_end(done_storage);

        let res = binary.builder.build_phi(ty, "storage_res");

        res.add_incoming(&[
            (&loaded_string, retrieve_block),
            (
                &binary
                    .module
                    .get_struct_type("struct.vector")
                    .unwrap()
                    .ptr_type(AddressSpace::default())
                    .const_null(),
                entry,
            ),
        ]);

        res.as_basic_value().into_pointer_value()
    }

    /// Read string from contract storage
    fn get_storage_bytes_subscript(
        &self,
        binary: &Binary<'a>,
        function: FunctionValue,
        slot: IntValue<'a>,
        index: IntValue<'a>,
        loc: Loc,
        ns: &Namespace,
    ) -> IntValue<'a> {
        emit_fluentbase_context!(binary);

        let slot_ptr = binary.builder.build_alloca(slot.get_type(), "slot");
        binary.builder.build_store(slot_ptr, slot);

        let (scratch_buf, scratch_len) = scratch_buf!();

        binary
            .builder
            .build_store(scratch_len, i32_const!(SCRATCH_SIZE as u64));

        let exists = seal_get_storage!(
            slot_ptr.into(),
            scratch_buf.into(),
        );

        log_return_code(binary, "seal_get_storage", exists);

        let exists = binary.builder.build_int_compare(
            IntPredicate::EQ,
            exists,
            i32_zero!(),
            "storage_exists",
        );

        let length = binary
            .builder
            .build_select(
                exists,
                binary
                    .builder
                    .build_load(binary.context.i32_type(), scratch_len, "string_len"),
                i32_zero!().into(),
                "string_length",
            )
            .into_int_value();

        // do bounds check on index
        let in_range =
            binary
                .builder
                .build_int_compare(IntPredicate::ULT, index, length, "index_in_range");

        let retrieve_block = binary.context.append_basic_block(function, "in_range");
        let bang_block = binary.context.append_basic_block(function, "bang_block");

        binary
            .builder
            .build_conditional_branch(in_range, retrieve_block, bang_block);

        binary.builder.position_at_end(bang_block);

        binary.log_runtime_error(
            self,
            "storage array index out of bounds".to_string(),
            Some(loc),
            ns,
        );
        self.assert_failure(binary, byte_ptr!().const_null(), i32_zero!());

        binary.builder.position_at_end(retrieve_block);

        let offset = unsafe {
            binary.builder.build_gep(
                binary.context.i8_type().array_type(SCRATCH_SIZE),
                binary.scratch.unwrap().as_pointer_value(),
                &[i32_zero!(), index],
                "data_offset",
            )
        };

        binary
            .builder
            .build_load(binary.context.i8_type(), offset, "value")
            .into_int_value()
    }

    fn set_storage_bytes_subscript(
        &self,
        binary: &Binary,
        function: FunctionValue,
        slot: IntValue,
        index: IntValue,
        val: IntValue,
        ns: &Namespace,
        loc: Loc,
    ) {
        emit_fluentbase_context!(binary);

        let slot_ptr = binary.builder.build_alloca(slot.get_type(), "slot");
        binary.builder.build_store(slot_ptr, slot);

        let (scratch_buf, scratch_len) = scratch_buf!();

        binary
            .builder
            .build_store(scratch_len, i32_const!(SCRATCH_SIZE as u64));

        let exists = seal_get_storage!(
            slot_ptr.into(),
            scratch_buf.into(),
        );

        log_return_code(binary, "seal_get_storage", exists);

        let exists = binary.builder.build_int_compare(
            IntPredicate::EQ,
            exists,
            i32_zero!(),
            "storage_exists",
        );

        let length = binary
            .builder
            .build_select(
                exists,
                binary
                    .builder
                    .build_load(binary.context.i32_type(), scratch_len, "string_len"),
                i32_zero!().into(),
                "string_length",
            )
            .into_int_value();

        // do bounds check on index
        let in_range =
            binary
                .builder
                .build_int_compare(IntPredicate::ULT, index, length, "index_in_range");

        let retrieve_block = binary.context.append_basic_block(function, "in_range");
        let bang_block = binary.context.append_basic_block(function, "bang_block");

        binary
            .builder
            .build_conditional_branch(in_range, retrieve_block, bang_block);

        binary.builder.position_at_end(bang_block);
        binary.log_runtime_error(
            self,
            "storage index out of bounds".to_string(),
            Some(loc),
            ns,
        );
        self.assert_failure(binary, byte_ptr!().const_null(), i32_zero!());

        binary.builder.position_at_end(retrieve_block);

        let offset = unsafe {
            binary.builder.build_gep(
                binary.context.i8_type().array_type(SCRATCH_SIZE),
                binary.scratch.unwrap().as_pointer_value(),
                &[i32_zero!(), index],
                "data_offset",
            )
        };

        // set the result
        binary.builder.build_store(offset, val);

        let ret = seal_set_storage!(
            slot_ptr.into(),
            scratch_buf.into()
        );

        log_return_code(binary, "seal_set_storage", ret);
    }

    /// Push a byte onto a bytes string in storage
    fn storage_push(
        &self,
        binary: &Binary<'a>,
        _function: FunctionValue,
        _ty: &ast::Type,
        slot: IntValue<'a>,
        val: Option<BasicValueEnum<'a>>,
        _ns: &ast::Namespace,
    ) -> BasicValueEnum<'a> {
        emit_fluentbase_context!(binary);

        let val = val.unwrap();

        let slot_ptr = binary.builder.build_alloca(slot.get_type(), "slot");
        binary.builder.build_store(slot_ptr, slot);

        let (scratch_buf, scratch_len) = scratch_buf!();

        // Since we are going to add one byte, we set the buffer length to one less. This will
        // trap for us if it does not fit, so we don't have to code this ourselves
        binary
            .builder
            .build_store(scratch_len, i32_const!(SCRATCH_SIZE as u64 - 1));

        let exists = seal_get_storage!(
            slot_ptr.into(),
            scratch_buf.into(),
        );

        log_return_code(binary, "seal_get_storage", exists);

        let exists = binary.builder.build_int_compare(
            IntPredicate::EQ,
            exists,
            i32_zero!(),
            "storage_exists",
        );

        let length = binary
            .builder
            .build_select(
                exists,
                binary
                    .builder
                    .build_load(binary.context.i32_type(), scratch_len, "string_len"),
                i32_zero!().into(),
                "string_length",
            )
            .into_int_value();

        // set the result
        let offset = unsafe {
            binary.builder.build_gep(
                binary.context.i8_type().array_type(SCRATCH_SIZE),
                binary.scratch.unwrap().as_pointer_value(),
                &[i32_zero!(), length],
                "data_offset",
            )
        };

        binary.builder.build_store(offset, val);

        // Set the new length
        let length = binary
            .builder
            .build_int_add(length, i32_const!(1), "new_length");

        let ret = seal_set_storage!(
            slot_ptr.into(),
            scratch_buf.into()
        );

        log_return_code(binary, "seal_set_storage", ret);

        val
    }

    /// Pop a value from a bytes string
    fn storage_pop(
        &self,
        binary: &Binary<'a>,
        function: FunctionValue<'a>,
        ty: &ast::Type,
        slot: IntValue<'a>,
        load: bool,
        ns: &ast::Namespace,
        loc: Loc,
    ) -> Option<BasicValueEnum<'a>> {
        emit_fluentbase_context!(binary);

        let slot_ptr = binary.builder.build_alloca(slot.get_type(), "slot");
        binary.builder.build_store(slot_ptr, slot);

        let (scratch_buf, scratch_len) = scratch_buf!();

        binary
            .builder
            .build_store(scratch_len, i32_const!(SCRATCH_SIZE as u64));

        let exists = seal_get_storage!(
            slot_ptr.into(),
            scratch_buf.into(),
        );

        log_return_code(binary, "seal_get_storage", exists);

        let exists = binary.builder.build_int_compare(
            IntPredicate::EQ,
            exists,
            i32_zero!(),
            "storage_exists",
        );

        let length = binary
            .builder
            .build_select(
                exists,
                binary
                    .builder
                    .build_load(binary.context.i32_type(), scratch_len, "string_len"),
                i32_zero!().into(),
                "string_length",
            )
            .into_int_value();

        // do bounds check on index
        let in_range = binary.builder.build_int_compare(
            IntPredicate::NE,
            i32_zero!(),
            length,
            "index_in_range",
        );

        let retrieve_block = binary.context.append_basic_block(function, "in_range");
        let bang_block = binary.context.append_basic_block(function, "bang_block");

        binary
            .builder
            .build_conditional_branch(in_range, retrieve_block, bang_block);

        binary.builder.position_at_end(bang_block);
        binary.log_runtime_error(
            self,
            "pop from empty storage array".to_string(),
            Some(loc),
            ns,
        );
        self.assert_failure(binary, byte_ptr!().const_null(), i32_zero!());

        binary.builder.position_at_end(retrieve_block);

        // Set the new length
        let new_length = binary
            .builder
            .build_int_sub(length, i32_const!(1), "new_length");

        let val = if load {
            let offset = unsafe {
                binary.builder.build_gep(
                    binary.context.i8_type().array_type(SCRATCH_SIZE),
                    binary.scratch.unwrap().as_pointer_value(),
                    &[i32_zero!(), new_length],
                    "data_offset",
                )
            };

            Some(
                binary
                    .builder
                    .build_load(binary.llvm_type(ty, ns), offset, "popped_value"),
            )
        } else {
            None
        };

        let ret = seal_set_storage!(
            slot_ptr.into(),
            scratch_buf.into()
        );

        log_return_code(binary, "seal_set_storage", ret);

        val
    }

    /// Calculate length of storage dynamic bytes
    fn storage_array_length(
        &self,
        binary: &Binary<'a>,
        _function: FunctionValue,
        slot: IntValue<'a>,
        _ty: &ast::Type,
        _ns: &ast::Namespace,
    ) -> IntValue<'a> {
        emit_fluentbase_context!(binary);

        let slot_ptr = binary.builder.build_alloca(slot.get_type(), "slot");
        binary.builder.build_store(slot_ptr, slot);

        let (scratch_buf, scratch_len) = scratch_buf!();

        binary
            .builder
            .build_store(scratch_len, i32_const!(SCRATCH_SIZE as u64));

        let exists = seal_get_storage!(
            slot_ptr.into(),
            scratch_buf.into(),
        );

        log_return_code(binary, "seal_get_storage", exists);

        let exists = binary.builder.build_int_compare(
            IntPredicate::EQ,
            exists,
            i32_zero!(),
            "storage_exists",
        );

        binary
            .builder
            .build_select(
                exists,
                binary
                    .builder
                    .build_load(binary.context.i32_type(), scratch_len, "string_len"),
                i32_zero!().into(),
                "string_length",
            )
            .into_int_value()
    }

    fn return_empty_abi(&self, binary: &Binary) {
        emit_fluentbase_context!(binary);

        call!(
            "_evm_return",
            &[
                byte_ptr!().const_zero().into(),
                i32_zero!().into()
            ]
        );

        binary.builder.build_unreachable();
    }

    fn return_code<'b>(&self, binary: &'b Binary, _ret: IntValue<'b>) {
        emit_fluentbase_context!(binary);

        // we can't return specific errors
        self.assert_failure(binary, byte_ptr!().const_zero(), i32_zero!());
    }

    /// Call the  keccak256 host function
    fn keccak256_hash(
        &self,
        binary: &Binary,
        src: PointerValue,
        length: IntValue,
        dest: PointerValue,
        _ns: &ast::Namespace,
    ) {
        emit_fluentbase_context!(binary);

        call!("_evm_keccak256", &[src.into(), length.into(), dest.into()]);
    }

    fn return_abi<'b>(&self, binary: &'b Binary, data: PointerValue<'b>, length: IntValue) {
        emit_fluentbase_context!(binary);
        call!(
            "_evm_return",
            &[data.into(), length.into()]
        );

        println!("Return abi: {:?}", data);
        binary.builder.build_unreachable();
    }

    fn return_abi_data<'b>(
        &self,
        binary: &Binary<'b>,
        data: PointerValue<'b>,
        data_len: BasicValueEnum<'b>,
    ) {
        emit_fluentbase_context!(binary);

        call!(
            "_evm_return",
            &[data.into(), data_len.into()]
        );

        binary
            .builder
            .build_return(Some(&binary.return_values[&ReturnCode::Success]));
    }

    fn assert_failure(&self, binary: &Binary, data: PointerValue, length: IntValue) {
        emit_fluentbase_context!(binary);

        call!("_evm_revert", &[data.into(), length.into()]);

        // Inserting an "unreachable" instruction signals to the LLVM optimizer
        // that any following code can not be reached.
        //
        // The contracts pallet guarantees to never return from "seal_return",
        // and we want to provide this higher level knowledge to the compiler.
        //
        // https://llvm.org/docs/LangRef.html#unreachable-instruction
        binary.builder.build_unreachable();
    }

    fn print(&self, binary: &Binary, string_ptr: PointerValue, string_len: IntValue) {
        emit_fluentbase_context!(binary);

        let ret = call!("debug_message", &[string_ptr.into(), string_len.into()])
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();

        log_return_code(binary, "seal_debug_message", ret);
    }

    fn create_contract<'b>(
        &mut self,
        binary: &Binary<'b>,
        function: FunctionValue<'b>,
        success: Option<&mut BasicValueEnum<'b>>,
        contract_no: usize,
        address: PointerValue<'b>,
        encoded_args: BasicValueEnum<'b>,
        encoded_args_len: BasicValueEnum<'b>,
        contract_args: ContractArgs<'b>,
        ns: &ast::Namespace,
        loc: Loc,
    ) {
        emit_fluentbase_context!(binary);

        let created_contract = &ns.contracts[contract_no];

        let code = created_contract.emit(ns, binary.options);

        let code = binary.emit_global_string(
            &format!("contract_{}_code", created_contract.name),
            &code,
            true,
        );

        // salt
        let salt_buf =
            binary.build_alloca(function, binary.context.i8_type().array_type(32), "salt");

        // let salt = contract_args.salt;
        // TODO: Remove and test simple call
        let salt = Some(contract_args.salt.unwrap_or_else(|| {
            let nonce = call!("instantiation_nonce", &[], "instantiation_nonce_ext")
                .try_as_basic_value()
                .left()
                .unwrap()
                .into_int_value();
            log_return_code(binary, "instantiation_nonce", nonce);
            let i256_t = binary.context.custom_width_int_type(256);
            binary
                .builder
                .build_int_z_extend_or_bit_cast(nonce, i256_t, "instantiation_nonce")
        }));

        let encoded_args = binary.vector_bytes(encoded_args);

        let value_ptr = binary
            .builder
            .build_alloca(binary.value_type(ns), "balance");

        // balance is a u128, make sure it's enough to cover existential_deposit
        if let Some(value) = contract_args.value {
            binary.builder.build_store(value_ptr, value);
        } else {
            binary.builder.build_store(value_ptr, binary.context.i128_type().const_zero());
        }

        if let Some(salt) = salt {
            binary.builder.build_store(salt_buf, salt);
            call!(
                "_evm_create2",
                &[
                    value_ptr.into(),
                    encoded_args.into(),
                    encoded_args_len.into(),
                    salt_buf.into(),
                    address.into(),
                ]
            );
        }
        else {
            call!(
                "_evm_create",
                &[
                    value_ptr.into(),
                    encoded_args.into(),
                    encoded_args_len.into(),
                    address.into(),
                ]
            );
        }

        let zero_address = binary.builder.build_alloca(binary.address_type(ns), "zero_address");
        call!(
            "__memset",
            &[
                zero_address.into(),
                binary.context.i8_type().const_int(0, false).into(),
                binary.context.i32_type().const_int(20, false).into(),
            ]
        );

        let res = binary.builder
            .build_call(
                binary.module.get_function("__memcmp").unwrap(),
                &[
                    address.into(),
                    binary.context.i32_type().const_int(20, false).into(),
                    zero_address.into(),
                    binary.context.i32_type().const_int(20, false).into(),
                ],
                "",
            )
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_int_value();

        let is_success =
            binary
                .builder
                .build_int_compare(IntPredicate::EQ, res, binary.context.bool_type().const_zero(), "success");

        log_return_code(binary, "create contract res", is_success);

        if let Some(success) = success {
            // we're in a try statement. This means:
            // return success or not in success variable; do not abort execution
            *success = is_success.into();
        } else {
            let success_block = binary.context.append_basic_block(function, "success");
            let bail_block = binary.context.append_basic_block(function, "bail");

            binary
                .builder
                .build_conditional_branch(is_success, success_block, bail_block);

            binary.builder.position_at_end(bail_block);

            binary.log_runtime_error(self, "contract creation failed".to_string(), Some(loc), ns);
            self.assert_failure(binary, byte_ptr!().const_null(), i32_zero!());

            binary.builder.position_at_end(success_block);
        }

    }

    /// Call external binary
    fn external_call<'b>(
        &self,
        binary: &Binary<'b>,
        function: FunctionValue<'b>,
        success: Option<&mut BasicValueEnum<'b>>,
        payload: PointerValue<'b>,
        payload_len: IntValue<'b>,
        address: Option<PointerValue<'b>>,
        contract_args: ContractArgs<'b>,
        call_type: ast::CallTy,
        ns: &ast::Namespace,
        loc: Loc,
    ) {
        emit_fluentbase_context!(binary);

        let (scratch_buf, scratch_len) = scratch_buf!();
        binary
            .builder
            .build_store(scratch_len, i32_const!(SCRATCH_SIZE as u64));

        let dest_ptr = binary
            .builder
            .build_alloca(binary.context.custom_width_int_type(8), "dest");

        // do the actual call
        match call_type {
            ast::CallTy::Regular => {
                let value_ptr = binary
                    .builder
                    .build_alloca(binary.value_type(ns), "balance");
                binary
                    .builder
                    .build_store(value_ptr, contract_args.value.unwrap());
                call!(
                    "_evm_call",
                    &[
                        contract_args.gas.unwrap().into(),
                        address.unwrap().into(),
                        value_ptr.into(),
                        payload.into(),
                        payload_len.into(),
                        scratch_buf.into(),
                        scratch_len.into(),
                        dest_ptr.into(),
                    ]
                );
                // log_return_code(binary, "seal_call", ret);
            }
            ast::CallTy::Delegate => {
                // delegate_call asks for a code hash instead of an address
                let hash_len = i32_const!(32); // FIXME: This is configurable like the address length
                let code_hash_out_ptr = binary.builder.build_array_alloca(
                    binary.context.i8_type(),
                    hash_len,
                    "code_hash_out_ptr",
                );
                let code_hash_out_len_ptr = binary
                    .builder
                    .build_alloca(binary.context.i32_type(), "code_hash_out_len_ptr");
                binary.builder.build_store(code_hash_out_len_ptr, hash_len);
                let code_hash_ret = call!(
                    "code_hash",
                    &[
                        address.unwrap().into(),
                        code_hash_out_ptr.into(),
                        code_hash_out_len_ptr.into(),
                    ]
                )
                .try_as_basic_value()
                .left()
                .unwrap()
                .into_int_value();
                log_return_code(binary, "seal_code_hash", code_hash_ret);

                let code_hash_found = binary.builder.build_int_compare(
                    IntPredicate::EQ,
                    code_hash_ret,
                    i32_zero!(),
                    "code_hash_found",
                );
                let entry = binary.builder.get_insert_block().unwrap();
                let call_block = binary
                    .context
                    .append_basic_block(function, "code_hash_found");
                let not_found_block = binary
                    .context
                    .append_basic_block(function, "code_hash_not_found");
                let done_block = binary.context.append_basic_block(function, "done_block");
                binary.builder.build_conditional_branch(
                    code_hash_found,
                    call_block,
                    not_found_block,
                );

                binary.builder.position_at_end(not_found_block);
                let msg = "delegatecall callee is not a contract account";
                binary.log_runtime_error(self, msg.into(), Some(loc), ns);
                binary.builder.build_unconditional_branch(done_block);

                binary.builder.position_at_end(call_block);
                let delegate_call_ret = call!(
                    "_evm_delegatecall",
                    &[
                        contract_args.gas.unwrap().into(),
                        address.unwrap().into(),
                        payload.into(),
                        payload_len.into(),
                        scratch_buf.into(),
                        scratch_len.into(),
                        dest_ptr.into(),
                    ]
                )
                .try_as_basic_value()
                .left()
                .unwrap()
                .into_int_value();
                // log_return_code(binary, "seal_delegate_call", delegate_call_ret);
                binary.builder.build_unconditional_branch(done_block);

                binary.builder.position_at_end(done_block);
                let ty = binary.context.i32_type();
                let ret = binary.builder.build_phi(ty, "storage_res");
                ret.add_incoming(&[(&code_hash_ret, not_found_block), (&ty.const_zero(), entry)]);
                ret.add_incoming(&[(&delegate_call_ret, call_block), (&ty.const_zero(), entry)]);
            }
            ast::CallTy::Static => unreachable!("sema does not allow this"),
        };

        let res = binary.builder.build_load(binary.context.bool_type(), dest_ptr, "result").into_int_value();
        let is_success =
            binary
                .builder
                .build_int_compare(IntPredicate::NE, res, binary.context.bool_type().const_zero(), "success");

        if let Some(success) = success {
            // we're in a try statement. This means:
            // do not abort execution; return success or not in success variable
            *success = is_success.into();
        } else {
            let success_block = binary.context.append_basic_block(function, "success");
            let bail_block = binary.context.append_basic_block(function, "bail");

            binary
                .builder
                .build_conditional_branch(is_success, success_block, bail_block);

            binary.builder.position_at_end(bail_block);

            binary.log_runtime_error(self, "external call failed".to_string(), Some(loc), ns);
            self.assert_failure(binary, byte_ptr!().const_null(), i32_zero!());

            binary.builder.position_at_end(success_block);
        }
    }

    /// Send value to address
    fn value_transfer<'b>(
        &self,
        binary: &Binary<'b>,
        function: FunctionValue,
        success: Option<&mut BasicValueEnum<'b>>,
        address: PointerValue<'b>,
        value: IntValue<'b>,
        ns: &ast::Namespace,
        loc: Loc,
    ) {
        emit_fluentbase_context!(binary);

        // balance is a u128
        let value_ptr = binary
            .builder
            .build_alloca(binary.value_type(ns), "balance");
        binary.builder.build_store(value_ptr, value);

        call!(
            "_evm_call",
            &[
                binary.context.i32_type().const_int(0, false).into(),
                address.into(),
                value_ptr.into(),
                binary.context.i32_type().const_int(0, false).into(),
                binary.context.i32_type().const_int(0, false).into(),
                binary.context.i32_type().const_int(0, false).into(),
                binary.context.i32_type().const_int(0, false).into(),
                binary.context.i32_type().const_int(0, false).into(),
            ]
        );
    }

    fn return_data<'b>(&self, binary: &Binary<'b>, _function: FunctionValue) -> PointerValue<'b> {
        emit_fluentbase_context!(binary);

        // The `seal_call` syscall leaves the return data in the scratch buffer
        let (scratch_buf, scratch_len) = scratch_buf!();
        let ty = binary.context.i32_type();
        let length = binary.builder.build_load(ty, scratch_len, "scratch_len");
        call!(
            "vector_new",
            &[length.into(), i32_const!(1).into(), scratch_buf.into(),]
        )
        .try_as_basic_value()
        .left()
        .unwrap()
        .into_pointer_value()
    }

    /// Polkadot value is usually 128 bits
    fn value_transferred<'b>(&self, binary: &Binary<'b>, ns: &ast::Namespace) -> IntValue<'b> {
        emit_fluentbase_context!(binary);

        let value = binary.builder.build_alloca(binary.value_type(ns), "value");

        // _evm_callvalue
        call!(
            "_evm_callvalue",
            &[value.into()],
            "value_transferred"
        );

        binary
            .builder
            .build_load(binary.value_type(ns), value, "value_transferred")
            .into_int_value()
    }

    /// Terminate execution, destroy contract and send remaining funds to addr
    fn selfdestruct<'b>(&self, binary: &Binary<'b>, addr: ArrayValue<'b>, ns: &ast::Namespace) {
        unimplemented!();
    }

    /// Crypto Hash
    fn hash<'b>(
        &self,
        binary: &Binary<'b>,
        _function: FunctionValue<'b>,

        hash: HashTy,
        input: PointerValue<'b>,
        input_len: IntValue<'b>,
        ns: &ast::Namespace,
    ) -> IntValue<'b> {
        emit_fluentbase_context!(binary);

        let (fname, hashlen) = match hash {
            HashTy::Keccak256 => ("hash_keccak_256", 32),
            HashTy::Ripemd160 => ("ripemd160", 20),
            HashTy::Sha256 => ("hash_sha2_256", 32),
            HashTy::Blake2_128 => ("hash_blake2_128", 16),
            HashTy::Blake2_256 => ("hash_blake2_256", 32),
        };

        let res =
            binary
                .builder
                .build_array_alloca(binary.context.i8_type(), i32_const!(hashlen), "res");

        call!(fname, &[input.into(), input_len.into(), res.into()], "hash");

        // bytes32 needs to reverse bytes
        let temp = binary.builder.build_alloca(
            binary.llvm_type(&ast::Type::Bytes(hashlen as u8), ns),
            "hash",
        );

        call!(
            "__beNtoleN",
            &[res.into(), temp.into(), i32_const!(hashlen).into()]
        );

        binary
            .builder
            .build_load(
                binary.llvm_type(&ast::Type::Bytes(hashlen as u8), ns),
                temp,
                "hash",
            )
            .into_int_value()
    }

    /// Emit event
    fn emit_event<'b>(
        &self,
        binary: &Binary<'b>,
        _function: FunctionValue<'b>,
        data: BasicValueEnum<'b>,
        topics: &[BasicValueEnum<'b>],
    ) {
        emit_fluentbase_context!(binary);

        let topic_count = topics.len();

        println!("Topic: count: {}", topic_count);

        let topics = topics.iter().map(|topic| {
            let dest = binary
                .builder
                .build_array_alloca(binary.context.i8_type(), binary.context.i32_type().const_int(32, false), "topic");
            call!(
                    "__memcpy",
                    &[
                        dest.into(),
                        binary.vector_bytes(*topic).into(),
                        binary.vector_len(*topic).into(),
                    ]
            );
            dest
        }).collect::<Vec<_>>();


        match topic_count {
            0 => {
                call!(
                    "_evm_log0",
                    &[
                        binary.vector_bytes(data).into(),
                        binary.vector_len(data).into(),
                    ]
                );
            }
            1 => {
                call!(
                    "_evm_log1",
                    &[
                        binary.vector_bytes(data).into(),
                        binary.vector_len(data).into(),
                        topics[0].into()
                    ]
                );
            }
            2 => {
                call!(
                    "_evm_log2",
                    &[
                        binary.vector_bytes(data).into(),
                        binary.vector_len(data).into(),
                        topics[0].into(),
                        topics[1].into(),
                    ]
                );
            }
            3 => {
                println!("Event 3");
                call!(
                    "_evm_log3",
                    &[
                        binary.vector_bytes(data).into(),
                        binary.vector_len(data).into(),
                        topics[0].into(),
                        topics[1].into(),
                        topics[2].into(),
                    ]
                );
            }
            4 => {
                call!(
                    "_evm_log4",
                    &[
                        binary.vector_bytes(data).into(),
                        binary.vector_len(data).into(),
                        topics[0].into(),
                        topics[1].into(),
                        topics[2].into(),
                        topics[3].into(),
                    ]
                );
            }
            _ => ()
        }
    }

    /// builtin expressions
    fn builtin<'b>(
        &self,
        binary: &Binary<'b>,
        expr: &codegen::Expression,
        vartab: &HashMap<usize, Variable<'b>>,
        function: FunctionValue<'b>,
        ns: &ast::Namespace,
    ) -> BasicValueEnum<'b> {
        emit_fluentbase_context!(binary);

        macro_rules! get_seal_value {
            ($name:literal, $func:literal, $width:expr) => {{
                let (scratch_buf, scratch_len) = scratch_buf!();

                binary.builder.build_store(
                    scratch_len,
                    binary
                        .context
                        .i32_type()
                        .const_int($width as u64 / 8, false),
                );

                call!($func, &[scratch_buf.into(), scratch_len.into()], $name);

                binary.builder.build_load(
                    binary.context.custom_width_int_type($width),
                    scratch_buf,
                    $name,
                )
            }};
        }

        match expr {
            codegen::Expression::Builtin {
                kind: codegen::Builtin::Calldata,
                ..
            } => {
                // allocate vector for input
                let v = call!(
                    "vector_new",
                    &[
                        binary
                            .builder
                            .build_load(
                                binary.context.i32_type(),
                                binary.calldata_len.as_pointer_value(),
                                "calldata_len"
                            )
                            .into(),
                        i32_const!(1).into(),
                        binary
                            .builder
                            .build_int_to_ptr(
                                binary.context.i32_type().const_all_ones(),
                                byte_ptr!(),
                                "no_initializer",
                            )
                            .into(),
                    ]
                )
                .try_as_basic_value()
                .left()
                .unwrap();

                let data = unsafe {
                    binary.builder.build_gep(
                        binary.context.get_struct_type("struct.vector").unwrap(),
                        v.into_pointer_value(),
                        &[i32_zero!(), i32_const!(2)],
                        "",
                    )
                };

                let (scratch_buf, scratch_len) = scratch_buf!();

                call!(
                    "_evm_codesize",
                    &[scratch_buf.into()],
                    "code_size"
                );

                // retrieve the data
                call!(
                    "_evm_codecopy",
                    &[
                        data.into(),
                        binary.context.i32_type().const_int(0, false).into(),
                        binary
                            .builder
                            .build_load(binary.value_type(ns), scratch_buf, "balance")
                            .into()
                    ],
                    "data"
                );

                v
            }
            codegen::Expression::Builtin {
                kind: codegen::Builtin::BlockNumber,
                ..
            } => {
                let (scratch_buf, scratch_len) = scratch_buf!();

                binary
                    .builder
                    .build_store(scratch_len, i32_const!(ns.value_length as u64));

                call!(
                    "_evm_number",
                    &[scratch_buf.into()],
                    ""
                );

                binary.builder.build_load(
                    binary
                        .context
                        .custom_width_int_type(ns.value_length as u32 * 8),
                    scratch_buf,
                    "block_number",
                )
            }
            codegen::Expression::Builtin {
                kind: codegen::Builtin::Timestamp,
                ..
            } => {
                let (scratch_buf, scratch_len) = scratch_buf!();

                binary
                    .builder
                    .build_store(scratch_len, i32_const!(ns.value_length as u64));

                call!(
                    "_evm_timestamp",
                    &[scratch_buf.into()],
                    ""
                );

                binary.builder.build_load(
                    binary
                        .context
                        .custom_width_int_type(ns.value_length as u32 * 8),
                    scratch_buf,
                    "timestamp",
                )
            }
            codegen::Expression::Builtin {
                kind: codegen::Builtin::Gasleft,
                ..
            } => {
                let (scratch_buf, scratch_len) = scratch_buf!();

                call!(
                    "_evm_gas",
                    &[scratch_buf.into()],
                    ""
                );

                binary.builder.build_load(
                    binary
                        .context
                        .custom_width_int_type(ns.value_length as u32 * 8),
                    scratch_buf,
                    "timestamp",
                )
            }
            codegen::Expression::Builtin {
                kind: codegen::Builtin::Gasprice,
                args,
                ..
            } => {
                // gasprice is available as "tx.gasprice" which will give you the price for one unit
                // of gas, or "tx.gasprice(uint64)" which will give you the price of N gas units

                //TODO: Ignore gas parameter. Need to add multiplying on gas_price result
                let gas = if args.is_empty() {
                    binary.context.i64_type().const_int(1, false)
                } else {
                    expression(self, binary, &args[0], vartab, function, ns).into_int_value()
                };

                let (scratch_buf, _) = scratch_buf!();

                call!(
                    "_evm_gasprice",
                    &[scratch_buf.into()],
                    ""
                );

                binary.builder.build_load(
                    binary
                        .context
                        .custom_width_int_type(ns.value_length as u32 * 8),
                    scratch_buf,
                    "price",
                )
            }
            codegen::Expression::Builtin {
                kind: codegen::Builtin::Sender,
                ..
            } => {
                let (scratch_buf, scratch_len) = scratch_buf!();
                println!("_evm_caller");
                call!(
                    "_evm_caller",
                    &[scratch_buf.into(),],
                    "seal_caller"
                );

                binary
                    .builder
                    .build_load(binary.address_type(ns), scratch_buf, "caller")
                // scratch_buf.as_basic_value_enum()
            }
            codegen::Expression::Builtin {
                kind: codegen::Builtin::Value,
                ..
            } => {
                let value = binary.builder.build_alloca(binary.value_type(ns), "value");

                let value_len = binary
                    .builder
                    .build_alloca(binary.context.i32_type(), "value_len");

                binary
                    .builder
                    .build_store(value_len, i32_const!(ns.value_length as u64));

                call!(
                   "_evm_callvalue",
                    &[value.into()],
                    "value_transferred"
                );

                binary
                    .builder
                    .build_load(binary.value_type(ns), value, "value_transferred")
            },
            codegen::Expression::Builtin {
                kind: codegen::Builtin::MinimumBalance,
                ..
            } => {
                let (scratch_buf, _) = scratch_buf!();

                binary.builder.build_store(scratch_buf, binary.context.i128_type().const_int(500, false));
                binary.builder.build_load(binary.value_type(ns), scratch_buf, "minimum_balance")
            }
            codegen::Expression::Builtin {
                kind: codegen::Builtin::GetAddress,
                ..
            } => {
                let (scratch_buf, scratch_len) = scratch_buf!();

                binary
                    .builder
                    .build_store(scratch_len, i32_const!(ns.address_length as u64));

                call!(
                    "_evm_address",
                    &[scratch_buf.into()],
                    "seal_address"
                );

                // The scratch buffer is a global buffer which gets overwritten by many syscalls.
                // Whenever an address is needed in the Polkadot target, we strongly recommend
                // to `Expression::Load` the return of GetAddress to work with GetAddress.
                scratch_buf.as_basic_value_enum()
            }
            codegen::Expression::Builtin {
                kind: codegen::Builtin::Balance,
                args, ..
            } => {

                let address = if args.is_empty() {

                    binary.context.i32_type().const_array(&[binary.context.i32_type().const_int(0, false);20])
                } else {
                    expression(self, binary, &args[0], vartab, function, ns).into_array_value()
                };

                let (scratch_buf, scratch_len) = scratch_buf!();

                binary.builder.build_store(scratch_buf, address);

                binary
                    .builder
                    .build_store(scratch_len, i32_const!(ns.value_length as u64));

                call!(
                    "_evm_balance",
                    &[scratch_buf.into(), scratch_buf.into()],
                    "seal_balance"
                );

                binary
                    .builder
                    .build_load(binary.value_type(ns), scratch_buf, "balance")
            }
            _ => unreachable!("{:?}", expr),
        }
    }

    fn storage_load(
        &self,
        binary: &Binary<'a>,
        ty: &Type,
        slot: &mut IntValue<'a>,
        function: FunctionValue,
        ns: &Namespace,
    ) -> BasicValueEnum<'a> {
        // The storage slot is an i256 accessed through a pointer, so we need
        // to store it
        let slot_ptr = binary.builder.build_alloca(slot.get_type(), "slot");

        self.storage_load_slot(binary, ty, slot, slot_ptr, function, ns)
    }

    fn storage_store(
        &self,
        binary: &Binary<'a>,
        ty: &Type,
        _existing: bool,
        slot: &mut IntValue<'a>,
        dest: BasicValueEnum<'a>,
        function: FunctionValue<'a>,
        ns: &Namespace,
    ) {
        let slot_ptr = binary.builder.build_alloca(slot.get_type(), "slot");

        self.storage_store_slot(binary, ty, slot, slot_ptr, dest, function, ns);
    }

    fn storage_delete(
        &self,
        bin: &Binary<'a>,
        ty: &Type,
        slot: &mut IntValue<'a>,
        function: FunctionValue<'a>,
        ns: &Namespace,
    ) {
        let slot_ptr = bin.builder.build_alloca(slot.get_type(), "slot");

        self.storage_delete_slot(bin, ty, slot, slot_ptr, function, ns);
    }

    fn builtin_function(
        &self,
        _binary: &Binary<'a>,
        _function: FunctionValue<'a>,
        builtin_func: &Function,
        _args: &[BasicMetadataValueEnum<'a>],
        _first_arg_type: BasicTypeEnum,
        _ns: &Namespace,
    ) -> Option<BasicValueEnum<'a>> {
        emit_fluentbase_context!(binary);

        match builtin_func.name.as_str() {
            _ => unimplemented!(),
        }
    }

    fn storage_subscript(
        &self,
        _bin: &Binary<'a>,
        _function: FunctionValue<'a>,
        _ty: &Type,
        _slot: IntValue<'a>,
        _index: BasicValueEnum<'a>,
        _ns: &Namespace,
    ) -> IntValue<'a> {
        // not needed for slot-based storage chains
        unimplemented!()
    }
}
