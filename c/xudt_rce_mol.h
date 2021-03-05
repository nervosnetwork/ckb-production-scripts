// Generated by Molecule 0.7.0

#define MOLECULEC_VERSION 7000
#define MOLECULE_API_VERSION_MIN 7000

#include "molecule_reader.h"
#include "molecule_builder.h"

#ifndef XUDT_RCE_H
#define XUDT_RCE_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef MOLECULE_API_DECORATOR
#define __DEFINE_MOLECULE_API_DECORATOR_XUDT_RCE
#define MOLECULE_API_DECORATOR
#endif /* MOLECULE_API_DECORATOR */

#include "blockchain.h"

/*
 * Reader APIs
 */

MOLECULE_API_DECORATOR  mol_errno       MolReader_ScriptVec_verify                      (const mol_seg_t*, bool);
#define                                 MolReader_ScriptVec_length(s)                   mol_dynvec_length(s)
#define                                 MolReader_ScriptVec_get(s, i)                   mol_dynvec_slice_by_index(s, i)
MOLECULE_API_DECORATOR  mol_errno       MolReader_ScriptVecOpt_verify                   (const mol_seg_t*, bool);
#define                                 MolReader_ScriptVecOpt_is_none(s)               mol_option_is_none(s)
MOLECULE_API_DECORATOR  mol_errno       MolReader_XudtWitnessInput_verify               (const mol_seg_t*, bool);
#define                                 MolReader_XudtWitnessInput_actual_field_count(s) mol_table_actual_field_count(s)
#define                                 MolReader_XudtWitnessInput_has_extra_fields(s)  mol_table_has_extra_fields(s, 2)
#define                                 MolReader_XudtWitnessInput_get_raw_extension_data(s) mol_table_slice_by_index(s, 0)
#define                                 MolReader_XudtWitnessInput_get_structure(s)     mol_table_slice_by_index(s, 1)
#define                                 MolReader_RCRule_verify(s, c)                   mol_verify_fixed_size(s, 33)
#define                                 MolReader_RCRule_get_smt_root(s)                mol_slice_by_offset(s, 0, 32)
#define                                 MolReader_RCRule_get_flags(s)                   mol_slice_by_offset(s, 32, 1)
#define                                 MolReader_RCCellVec_verify(s, c)                mol_fixvec_verify(s, 32)
#define                                 MolReader_RCCellVec_length(s)                   mol_fixvec_length(s)
#define                                 MolReader_RCCellVec_get(s, i)                   mol_fixvec_slice_by_index(s, 32, i)
MOLECULE_API_DECORATOR  mol_errno       MolReader_RCData_verify                         (const mol_seg_t*, bool);
#define                                 MolReader_RCData_unpack(s)                      mol_union_unpack(s)
#define                                 MolReader_SmtProof_verify(s, c)                 mol_fixvec_verify(s, 1)
#define                                 MolReader_SmtProof_length(s)                    mol_fixvec_length(s)
#define                                 MolReader_SmtProof_get(s, i)                    mol_fixvec_slice_by_index(s, 1, i)
#define                                 MolReader_SmtProof_raw_bytes(s)                 mol_fixvec_slice_raw_bytes(s)
MOLECULE_API_DECORATOR  mol_errno       MolReader_SmtProofVec_verify                    (const mol_seg_t*, bool);
#define                                 MolReader_SmtProofVec_length(s)                 mol_dynvec_length(s)
#define                                 MolReader_SmtProofVec_get(s, i)                 mol_dynvec_slice_by_index(s, i)
#define                                 MolReader_SmtUpdateItem_verify(s, c)            mol_verify_fixed_size(s, 96)
#define                                 MolReader_SmtUpdateItem_get_key(s)              mol_slice_by_offset(s, 0, 32)
#define                                 MolReader_SmtUpdateItem_get_value(s)            mol_slice_by_offset(s, 32, 32)
#define                                 MolReader_SmtUpdateItem_get_old_value(s)        mol_slice_by_offset(s, 64, 32)
#define                                 MolReader_SmtUpdateVec_verify(s, c)             mol_fixvec_verify(s, 96)
#define                                 MolReader_SmtUpdateVec_length(s)                mol_fixvec_length(s)
#define                                 MolReader_SmtUpdateVec_get(s, i)                mol_fixvec_slice_by_index(s, 96, i)
MOLECULE_API_DECORATOR  mol_errno       MolReader_SmtUpdate_verify                      (const mol_seg_t*, bool);
#define                                 MolReader_SmtUpdate_actual_field_count(s)       mol_table_actual_field_count(s)
#define                                 MolReader_SmtUpdate_has_extra_fields(s)         mol_table_has_extra_fields(s, 2)
#define                                 MolReader_SmtUpdate_get_update(s)               mol_table_slice_by_index(s, 0)
#define                                 MolReader_SmtUpdate_get_proof(s)                mol_table_slice_by_index(s, 1)
MOLECULE_API_DECORATOR  mol_errno       MolReader_XudtData_verify                       (const mol_seg_t*, bool);
#define                                 MolReader_XudtData_actual_field_count(s)        mol_table_actual_field_count(s)
#define                                 MolReader_XudtData_has_extra_fields(s)          mol_table_has_extra_fields(s, 2)
#define                                 MolReader_XudtData_get_lock(s)                  mol_table_slice_by_index(s, 0)
#define                                 MolReader_XudtData_get_data(s)                  mol_table_slice_by_index(s, 1)

/*
 * Builder APIs
 */

#define                                 MolBuilder_ScriptVec_init(b)                    mol_builder_initialize_with_capacity(b, 1024, 64)
#define                                 MolBuilder_ScriptVec_push(b, p, l)              mol_dynvec_builder_push(b, p, l)
#define                                 MolBuilder_ScriptVec_build(b)                   mol_dynvec_builder_finalize(b)
#define                                 MolBuilder_ScriptVec_clear(b)                   mol_builder_discard(b)
#define                                 MolBuilder_ScriptVecOpt_init(b)                 mol_builder_initialize_fixed_size(b, 0)
#define                                 MolBuilder_ScriptVecOpt_set(b, p, l)            mol_option_builder_set(b, p, l)
#define                                 MolBuilder_ScriptVecOpt_build(b)                mol_builder_finalize_simple(b)
#define                                 MolBuilder_ScriptVecOpt_clear(b)                mol_builder_discard(b)
#define                                 MolBuilder_XudtWitnessInput_init(b)             mol_table_builder_initialize(b, 64, 2)
#define                                 MolBuilder_XudtWitnessInput_set_raw_extension_data(b, p, l) mol_table_builder_add(b, 0, p, l)
#define                                 MolBuilder_XudtWitnessInput_set_structure(b, p, l) mol_table_builder_add(b, 1, p, l)
MOLECULE_API_DECORATOR  mol_seg_res_t   MolBuilder_XudtWitnessInput_build               (mol_builder_t);
#define                                 MolBuilder_XudtWitnessInput_clear(b)            mol_builder_discard(b)
#define                                 MolBuilder_RCRule_init(b)                       mol_builder_initialize_fixed_size(b, 33)
#define                                 MolBuilder_RCRule_set_smt_root(b, p)            mol_builder_set_by_offset(b, 0, p, 32)
#define                                 MolBuilder_RCRule_set_flags(b, p)               mol_builder_set_byte_by_offset(b, 32, p)
#define                                 MolBuilder_RCRule_build(b)                      mol_builder_finalize_simple(b)
#define                                 MolBuilder_RCRule_clear(b)                      mol_builder_discard(b)
#define                                 MolBuilder_RCCellVec_init(b)                    mol_fixvec_builder_initialize(b, 512)
#define                                 MolBuilder_RCCellVec_push(b, p)                 mol_fixvec_builder_push(b, p, 32)
#define                                 MolBuilder_RCCellVec_build(b)                   mol_fixvec_builder_finalize(b)
#define                                 MolBuilder_RCCellVec_clear(b)                   mol_builder_discard(b)
#define                                 MolBuilder_RCData_init(b)                       mol_union_builder_initialize(b, 64, 0, &MolDefault_RCRule, 33)
#define                                 MolBuilder_RCData_set_RCRule(b, p, l)           mol_union_builder_set(b, 0, p, l)
#define                                 MolBuilder_RCData_set_RCCellVec(b, p, l)        mol_union_builder_set(b, 1, p, l)
#define                                 MolBuilder_RCData_build(b)                      mol_builder_finalize_simple(b)
#define                                 MolBuilder_RCData_clear(b)                      mol_builder_discard(b)
#define                                 MolBuilder_SmtProof_init(b)                     mol_fixvec_builder_initialize(b, 16)
#define                                 MolBuilder_SmtProof_push(b, p)                  mol_fixvec_builder_push_byte(b, p)
#define                                 MolBuilder_SmtProof_build(b)                    mol_fixvec_builder_finalize(b)
#define                                 MolBuilder_SmtProof_clear(b)                    mol_builder_discard(b)
#define                                 MolBuilder_SmtProofVec_init(b)                  mol_builder_initialize_with_capacity(b, 64, 64)
#define                                 MolBuilder_SmtProofVec_push(b, p, l)            mol_dynvec_builder_push(b, p, l)
#define                                 MolBuilder_SmtProofVec_build(b)                 mol_dynvec_builder_finalize(b)
#define                                 MolBuilder_SmtProofVec_clear(b)                 mol_builder_discard(b)
#define                                 MolBuilder_SmtUpdateItem_init(b)                mol_builder_initialize_fixed_size(b, 96)
#define                                 MolBuilder_SmtUpdateItem_set_key(b, p)          mol_builder_set_by_offset(b, 0, p, 32)
#define                                 MolBuilder_SmtUpdateItem_set_value(b, p)        mol_builder_set_by_offset(b, 32, p, 32)
#define                                 MolBuilder_SmtUpdateItem_set_old_value(b, p)    mol_builder_set_by_offset(b, 64, p, 32)
#define                                 MolBuilder_SmtUpdateItem_build(b)               mol_builder_finalize_simple(b)
#define                                 MolBuilder_SmtUpdateItem_clear(b)               mol_builder_discard(b)
#define                                 MolBuilder_SmtUpdateVec_init(b)                 mol_fixvec_builder_initialize(b, 2048)
#define                                 MolBuilder_SmtUpdateVec_push(b, p)              mol_fixvec_builder_push(b, p, 96)
#define                                 MolBuilder_SmtUpdateVec_build(b)                mol_fixvec_builder_finalize(b)
#define                                 MolBuilder_SmtUpdateVec_clear(b)                mol_builder_discard(b)
#define                                 MolBuilder_SmtUpdate_init(b)                    mol_table_builder_initialize(b, 128, 2)
#define                                 MolBuilder_SmtUpdate_set_update(b, p, l)        mol_table_builder_add(b, 0, p, l)
#define                                 MolBuilder_SmtUpdate_set_proof(b, p, l)         mol_table_builder_add(b, 1, p, l)
MOLECULE_API_DECORATOR  mol_seg_res_t   MolBuilder_SmtUpdate_build                      (mol_builder_t);
#define                                 MolBuilder_SmtUpdate_clear(b)                   mol_builder_discard(b)
#define                                 MolBuilder_XudtData_init(b)                     mol_table_builder_initialize(b, 128, 2)
#define                                 MolBuilder_XudtData_set_lock(b, p, l)           mol_table_builder_add(b, 0, p, l)
#define                                 MolBuilder_XudtData_set_data(b, p, l)           mol_table_builder_add(b, 1, p, l)
MOLECULE_API_DECORATOR  mol_seg_res_t   MolBuilder_XudtData_build                       (mol_builder_t);
#define                                 MolBuilder_XudtData_clear(b)                    mol_builder_discard(b)

/*
 * Default Value
 */

#define ____ 0x00

MOLECULE_API_DECORATOR const uint8_t MolDefault_ScriptVec[4]     =  {0x04, ____, ____, ____};
MOLECULE_API_DECORATOR const uint8_t MolDefault_ScriptVecOpt[0]  =  {};
MOLECULE_API_DECORATOR const uint8_t MolDefault_XudtWitnessInput[16] =  {
    0x10, ____, ____, ____, 0x0c, ____, ____, ____, 0x0c, ____, ____, ____,
    0x04, ____, ____, ____,
};
MOLECULE_API_DECORATOR const uint8_t MolDefault_RCRule[33]       =  {
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____,
};
MOLECULE_API_DECORATOR const uint8_t MolDefault_RCCellVec[4]     =  {____, ____, ____, ____};
MOLECULE_API_DECORATOR const uint8_t MolDefault_RCData[37]       =  {
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____,
};
MOLECULE_API_DECORATOR const uint8_t MolDefault_SmtProof[4]      =  {____, ____, ____, ____};
MOLECULE_API_DECORATOR const uint8_t MolDefault_SmtProofVec[4]   =  {0x04, ____, ____, ____};
MOLECULE_API_DECORATOR const uint8_t MolDefault_SmtUpdateItem[96] =  {
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
};
MOLECULE_API_DECORATOR const uint8_t MolDefault_SmtUpdateVec[4]  =  {____, ____, ____, ____};
MOLECULE_API_DECORATOR const uint8_t MolDefault_SmtUpdate[20]    =  {
    0x14, ____, ____, ____, 0x0c, ____, ____, ____, 0x10, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____,
};
MOLECULE_API_DECORATOR const uint8_t MolDefault_XudtData[20]     =  {
    0x14, ____, ____, ____, 0x0c, ____, ____, ____, 0x10, ____, ____, ____,
    ____, ____, ____, ____, 0x04, ____, ____, ____,
};

#undef ____

/*
 * Reader Functions
 */

MOLECULE_API_DECORATOR mol_errno MolReader_ScriptVec_verify (const mol_seg_t *input, bool compatible) {
    if (input->size < MOL_NUM_T_SIZE) {
        return MOL_ERR_HEADER;
    }
    uint8_t *ptr = input->ptr;
    mol_num_t total_size = mol_unpack_number(ptr);
    if (input->size != total_size) {
        return MOL_ERR_TOTAL_SIZE;
    }
    if (input->size == MOL_NUM_T_SIZE) {
        return MOL_OK;
    }
    if (input->size < MOL_NUM_T_SIZE * 2) {
        return MOL_ERR_HEADER;
    }
    ptr += MOL_NUM_T_SIZE;
    mol_num_t offset = mol_unpack_number(ptr);
    if (offset % 4 > 0 || offset < MOL_NUM_T_SIZE*2) {
        return MOL_ERR_OFFSET;
    }
    mol_num_t item_count = offset / 4 - 1;
    if (input->size < MOL_NUM_T_SIZE*(item_count+1)) {
        return MOL_ERR_HEADER;
    }
    mol_num_t end;
    for (mol_num_t i=1; i<item_count; i++) {
        ptr += MOL_NUM_T_SIZE;
        end = mol_unpack_number(ptr);
        if (offset > end) {
            return MOL_ERR_OFFSET;
        }
        mol_seg_t inner;
        inner.ptr = input->ptr + offset;
        inner.size = end - offset;
        mol_errno errno = MolReader_Script_verify(&inner, compatible);
        if (errno != MOL_OK) {
            return MOL_ERR_DATA;
        }
        offset = end;
    }
    if (offset > total_size) {
        return MOL_ERR_OFFSET;
    }
    mol_seg_t inner;
    inner.ptr = input->ptr + offset;
    inner.size = total_size - offset;
    return MolReader_Script_verify(&inner, compatible);
}
MOLECULE_API_DECORATOR mol_errno MolReader_ScriptVecOpt_verify (const mol_seg_t *input, bool compatible) {
    if (input->size != 0) {
        return MolReader_ScriptVec_verify(input, compatible);
    } else {
        return MOL_OK;
    }
}
MOLECULE_API_DECORATOR mol_errno MolReader_XudtWitnessInput_verify (const mol_seg_t *input, bool compatible) {
    if (input->size < MOL_NUM_T_SIZE) {
        return MOL_ERR_HEADER;
    }
    uint8_t *ptr = input->ptr;
    mol_num_t total_size = mol_unpack_number(ptr);
    if (input->size != total_size) {
        return MOL_ERR_TOTAL_SIZE;
    }
    if (input->size < MOL_NUM_T_SIZE * 2) {
        return MOL_ERR_HEADER;
    }
    ptr += MOL_NUM_T_SIZE;
    mol_num_t offset = mol_unpack_number(ptr);
    if (offset % 4 > 0 || offset < MOL_NUM_T_SIZE*2) {
        return MOL_ERR_OFFSET;
    }
    mol_num_t field_count = offset / 4 - 1;
    if (field_count < 2) {
        return MOL_ERR_FIELD_COUNT;
    } else if (!compatible && field_count > 2) {
        return MOL_ERR_FIELD_COUNT;
    }
    if (input->size < MOL_NUM_T_SIZE*(field_count+1)){
        return MOL_ERR_HEADER;
    }
    mol_num_t offsets[field_count+1];
    offsets[0] = offset;
    for (mol_num_t i=1; i<field_count; i++) {
        ptr += MOL_NUM_T_SIZE;
        offsets[i] = mol_unpack_number(ptr);
        if (offsets[i-1] > offsets[i]) {
            return MOL_ERR_OFFSET;
        }
    }
    if (offsets[field_count-1] > total_size) {
        return MOL_ERR_OFFSET;
    }
    offsets[field_count] = total_size;
        mol_seg_t inner;
        mol_errno errno;
        inner.ptr = input->ptr + offsets[0];
        inner.size = offsets[1] - offsets[0];
        errno = MolReader_ScriptVecOpt_verify(&inner, compatible);
        if (errno != MOL_OK) {
            return MOL_ERR_DATA;
        }
        inner.ptr = input->ptr + offsets[1];
        inner.size = offsets[2] - offsets[1];
        errno = MolReader_BytesVec_verify(&inner, compatible);
        if (errno != MOL_OK) {
            return MOL_ERR_DATA;
        }
    return MOL_OK;
}
MOLECULE_API_DECORATOR mol_errno MolReader_RCData_verify (const mol_seg_t *input, bool compatible) {
    if (input->size < MOL_NUM_T_SIZE) {
        return MOL_ERR_HEADER;
    }
    mol_num_t item_id = mol_unpack_number(input->ptr);
    mol_seg_t inner;
    inner.ptr = input->ptr + MOL_NUM_T_SIZE;
    inner.size = input->size - MOL_NUM_T_SIZE;
    switch(item_id) {
        case 0:
            return MolReader_RCRule_verify(&inner, compatible);
        case 1:
            return MolReader_RCCellVec_verify(&inner, compatible);
        default:
            return MOL_ERR_UNKNOWN_ITEM;
    }
}
MOLECULE_API_DECORATOR mol_errno MolReader_SmtProofVec_verify (const mol_seg_t *input, bool compatible) {
    if (input->size < MOL_NUM_T_SIZE) {
        return MOL_ERR_HEADER;
    }
    uint8_t *ptr = input->ptr;
    mol_num_t total_size = mol_unpack_number(ptr);
    if (input->size != total_size) {
        return MOL_ERR_TOTAL_SIZE;
    }
    if (input->size == MOL_NUM_T_SIZE) {
        return MOL_OK;
    }
    if (input->size < MOL_NUM_T_SIZE * 2) {
        return MOL_ERR_HEADER;
    }
    ptr += MOL_NUM_T_SIZE;
    mol_num_t offset = mol_unpack_number(ptr);
    if (offset % 4 > 0 || offset < MOL_NUM_T_SIZE*2) {
        return MOL_ERR_OFFSET;
    }
    mol_num_t item_count = offset / 4 - 1;
    if (input->size < MOL_NUM_T_SIZE*(item_count+1)) {
        return MOL_ERR_HEADER;
    }
    mol_num_t end;
    for (mol_num_t i=1; i<item_count; i++) {
        ptr += MOL_NUM_T_SIZE;
        end = mol_unpack_number(ptr);
        if (offset > end) {
            return MOL_ERR_OFFSET;
        }
        mol_seg_t inner;
        inner.ptr = input->ptr + offset;
        inner.size = end - offset;
        mol_errno errno = MolReader_SmtProof_verify(&inner, compatible);
        if (errno != MOL_OK) {
            return MOL_ERR_DATA;
        }
        offset = end;
    }
    if (offset > total_size) {
        return MOL_ERR_OFFSET;
    }
    mol_seg_t inner;
    inner.ptr = input->ptr + offset;
    inner.size = total_size - offset;
    return MolReader_SmtProof_verify(&inner, compatible);
}
MOLECULE_API_DECORATOR mol_errno MolReader_SmtUpdate_verify (const mol_seg_t *input, bool compatible) {
    if (input->size < MOL_NUM_T_SIZE) {
        return MOL_ERR_HEADER;
    }
    uint8_t *ptr = input->ptr;
    mol_num_t total_size = mol_unpack_number(ptr);
    if (input->size != total_size) {
        return MOL_ERR_TOTAL_SIZE;
    }
    if (input->size < MOL_NUM_T_SIZE * 2) {
        return MOL_ERR_HEADER;
    }
    ptr += MOL_NUM_T_SIZE;
    mol_num_t offset = mol_unpack_number(ptr);
    if (offset % 4 > 0 || offset < MOL_NUM_T_SIZE*2) {
        return MOL_ERR_OFFSET;
    }
    mol_num_t field_count = offset / 4 - 1;
    if (field_count < 2) {
        return MOL_ERR_FIELD_COUNT;
    } else if (!compatible && field_count > 2) {
        return MOL_ERR_FIELD_COUNT;
    }
    if (input->size < MOL_NUM_T_SIZE*(field_count+1)){
        return MOL_ERR_HEADER;
    }
    mol_num_t offsets[field_count+1];
    offsets[0] = offset;
    for (mol_num_t i=1; i<field_count; i++) {
        ptr += MOL_NUM_T_SIZE;
        offsets[i] = mol_unpack_number(ptr);
        if (offsets[i-1] > offsets[i]) {
            return MOL_ERR_OFFSET;
        }
    }
    if (offsets[field_count-1] > total_size) {
        return MOL_ERR_OFFSET;
    }
    offsets[field_count] = total_size;
        mol_seg_t inner;
        mol_errno errno;
        inner.ptr = input->ptr + offsets[0];
        inner.size = offsets[1] - offsets[0];
        errno = MolReader_SmtUpdateVec_verify(&inner, compatible);
        if (errno != MOL_OK) {
            return MOL_ERR_DATA;
        }
        inner.ptr = input->ptr + offsets[1];
        inner.size = offsets[2] - offsets[1];
        errno = MolReader_SmtProof_verify(&inner, compatible);
        if (errno != MOL_OK) {
            return MOL_ERR_DATA;
        }
    return MOL_OK;
}
MOLECULE_API_DECORATOR mol_errno MolReader_XudtData_verify (const mol_seg_t *input, bool compatible) {
    if (input->size < MOL_NUM_T_SIZE) {
        return MOL_ERR_HEADER;
    }
    uint8_t *ptr = input->ptr;
    mol_num_t total_size = mol_unpack_number(ptr);
    if (input->size != total_size) {
        return MOL_ERR_TOTAL_SIZE;
    }
    if (input->size < MOL_NUM_T_SIZE * 2) {
        return MOL_ERR_HEADER;
    }
    ptr += MOL_NUM_T_SIZE;
    mol_num_t offset = mol_unpack_number(ptr);
    if (offset % 4 > 0 || offset < MOL_NUM_T_SIZE*2) {
        return MOL_ERR_OFFSET;
    }
    mol_num_t field_count = offset / 4 - 1;
    if (field_count < 2) {
        return MOL_ERR_FIELD_COUNT;
    } else if (!compatible && field_count > 2) {
        return MOL_ERR_FIELD_COUNT;
    }
    if (input->size < MOL_NUM_T_SIZE*(field_count+1)){
        return MOL_ERR_HEADER;
    }
    mol_num_t offsets[field_count+1];
    offsets[0] = offset;
    for (mol_num_t i=1; i<field_count; i++) {
        ptr += MOL_NUM_T_SIZE;
        offsets[i] = mol_unpack_number(ptr);
        if (offsets[i-1] > offsets[i]) {
            return MOL_ERR_OFFSET;
        }
    }
    if (offsets[field_count-1] > total_size) {
        return MOL_ERR_OFFSET;
    }
    offsets[field_count] = total_size;
        mol_seg_t inner;
        mol_errno errno;
        inner.ptr = input->ptr + offsets[0];
        inner.size = offsets[1] - offsets[0];
        errno = MolReader_Bytes_verify(&inner, compatible);
        if (errno != MOL_OK) {
            return MOL_ERR_DATA;
        }
        inner.ptr = input->ptr + offsets[1];
        inner.size = offsets[2] - offsets[1];
        errno = MolReader_BytesVec_verify(&inner, compatible);
        if (errno != MOL_OK) {
            return MOL_ERR_DATA;
        }
    return MOL_OK;
}

/*
 * Builder Functions
 */

MOLECULE_API_DECORATOR mol_seg_res_t MolBuilder_XudtWitnessInput_build (mol_builder_t builder) {
    mol_seg_res_t res;
    res.errno = MOL_OK;
    mol_num_t offset = 12;
    mol_num_t len;
    res.seg.size = offset;
    len = builder.number_ptr[1];
    res.seg.size += len == 0 ? 0 : len;
    len = builder.number_ptr[3];
    res.seg.size += len == 0 ? 4 : len;
    res.seg.ptr = (uint8_t*)malloc(res.seg.size);
    uint8_t *dst = res.seg.ptr;
    mol_pack_number(dst, &res.seg.size);
    dst += MOL_NUM_T_SIZE;
    mol_pack_number(dst, &offset);
    dst += MOL_NUM_T_SIZE;
    len = builder.number_ptr[1];
    offset += len == 0 ? 0 : len;
    mol_pack_number(dst, &offset);
    dst += MOL_NUM_T_SIZE;
    len = builder.number_ptr[3];
    offset += len == 0 ? 4 : len;
    uint8_t *src = builder.data_ptr;
    len = builder.number_ptr[1];
    if (len == 0) {
        len = 0;
        memcpy(dst, &MolDefault_ScriptVecOpt, len);
    } else {
        mol_num_t of = builder.number_ptr[0];
        memcpy(dst, src+of, len);
    }
    dst += len;
    len = builder.number_ptr[3];
    if (len == 0) {
        len = 4;
        memcpy(dst, &MolDefault_BytesVec, len);
    } else {
        mol_num_t of = builder.number_ptr[2];
        memcpy(dst, src+of, len);
    }
    dst += len;
    mol_builder_discard(builder);
    return res;
}
MOLECULE_API_DECORATOR mol_seg_res_t MolBuilder_SmtUpdate_build (mol_builder_t builder) {
    mol_seg_res_t res;
    res.errno = MOL_OK;
    mol_num_t offset = 12;
    mol_num_t len;
    res.seg.size = offset;
    len = builder.number_ptr[1];
    res.seg.size += len == 0 ? 4 : len;
    len = builder.number_ptr[3];
    res.seg.size += len == 0 ? 4 : len;
    res.seg.ptr = (uint8_t*)malloc(res.seg.size);
    uint8_t *dst = res.seg.ptr;
    mol_pack_number(dst, &res.seg.size);
    dst += MOL_NUM_T_SIZE;
    mol_pack_number(dst, &offset);
    dst += MOL_NUM_T_SIZE;
    len = builder.number_ptr[1];
    offset += len == 0 ? 4 : len;
    mol_pack_number(dst, &offset);
    dst += MOL_NUM_T_SIZE;
    len = builder.number_ptr[3];
    offset += len == 0 ? 4 : len;
    uint8_t *src = builder.data_ptr;
    len = builder.number_ptr[1];
    if (len == 0) {
        len = 4;
        memcpy(dst, &MolDefault_SmtUpdateVec, len);
    } else {
        mol_num_t of = builder.number_ptr[0];
        memcpy(dst, src+of, len);
    }
    dst += len;
    len = builder.number_ptr[3];
    if (len == 0) {
        len = 4;
        memcpy(dst, &MolDefault_SmtProof, len);
    } else {
        mol_num_t of = builder.number_ptr[2];
        memcpy(dst, src+of, len);
    }
    dst += len;
    mol_builder_discard(builder);
    return res;
}
MOLECULE_API_DECORATOR mol_seg_res_t MolBuilder_XudtData_build (mol_builder_t builder) {
    mol_seg_res_t res;
    res.errno = MOL_OK;
    mol_num_t offset = 12;
    mol_num_t len;
    res.seg.size = offset;
    len = builder.number_ptr[1];
    res.seg.size += len == 0 ? 4 : len;
    len = builder.number_ptr[3];
    res.seg.size += len == 0 ? 4 : len;
    res.seg.ptr = (uint8_t*)malloc(res.seg.size);
    uint8_t *dst = res.seg.ptr;
    mol_pack_number(dst, &res.seg.size);
    dst += MOL_NUM_T_SIZE;
    mol_pack_number(dst, &offset);
    dst += MOL_NUM_T_SIZE;
    len = builder.number_ptr[1];
    offset += len == 0 ? 4 : len;
    mol_pack_number(dst, &offset);
    dst += MOL_NUM_T_SIZE;
    len = builder.number_ptr[3];
    offset += len == 0 ? 4 : len;
    uint8_t *src = builder.data_ptr;
    len = builder.number_ptr[1];
    if (len == 0) {
        len = 4;
        memcpy(dst, &MolDefault_Bytes, len);
    } else {
        mol_num_t of = builder.number_ptr[0];
        memcpy(dst, src+of, len);
    }
    dst += len;
    len = builder.number_ptr[3];
    if (len == 0) {
        len = 4;
        memcpy(dst, &MolDefault_BytesVec, len);
    } else {
        mol_num_t of = builder.number_ptr[2];
        memcpy(dst, src+of, len);
    }
    dst += len;
    mol_builder_discard(builder);
    return res;
}

#ifdef __DEFINE_MOLECULE_API_DECORATOR_XUDT_RCE
#undef MOLECULE_API_DECORATOR
#undef __DEFINE_MOLECULE_API_DECORATOR_XUDT_RCE
#endif /* __DEFINE_MOLECULE_API_DECORATOR_XUDT_RCE */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* XUDT_RCE_H */
