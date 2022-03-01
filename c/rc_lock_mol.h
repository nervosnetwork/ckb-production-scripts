// Generated by Molecule 0.7.2

#define MOLECULEC_VERSION 7000
#define MOLECULE_API_VERSION_MIN 7000

#include "molecule_reader.h"
#include "molecule_builder.h"

#ifndef RC_LOCK_H
#define RC_LOCK_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef MOLECULE_API_DECORATOR
#define __DEFINE_MOLECULE_API_DECORATOR_RC_LOCK
#define MOLECULE_API_DECORATOR
#endif /* MOLECULE_API_DECORATOR */

#include "xudt_rce_mol.h"

/*
 * Reader APIs
 */

#define                                 MolReader_Auth_verify(s, c)                     mol_verify_fixed_size(s, 21)
#define                                 MolReader_Auth_get_nth0(s)                      mol_slice_by_offset(s, 0, 1)
#define                                 MolReader_Auth_get_nth1(s)                      mol_slice_by_offset(s, 1, 1)
#define                                 MolReader_Auth_get_nth2(s)                      mol_slice_by_offset(s, 2, 1)
#define                                 MolReader_Auth_get_nth3(s)                      mol_slice_by_offset(s, 3, 1)
#define                                 MolReader_Auth_get_nth4(s)                      mol_slice_by_offset(s, 4, 1)
#define                                 MolReader_Auth_get_nth5(s)                      mol_slice_by_offset(s, 5, 1)
#define                                 MolReader_Auth_get_nth6(s)                      mol_slice_by_offset(s, 6, 1)
#define                                 MolReader_Auth_get_nth7(s)                      mol_slice_by_offset(s, 7, 1)
#define                                 MolReader_Auth_get_nth8(s)                      mol_slice_by_offset(s, 8, 1)
#define                                 MolReader_Auth_get_nth9(s)                      mol_slice_by_offset(s, 9, 1)
#define                                 MolReader_Auth_get_nth10(s)                     mol_slice_by_offset(s, 10, 1)
#define                                 MolReader_Auth_get_nth11(s)                     mol_slice_by_offset(s, 11, 1)
#define                                 MolReader_Auth_get_nth12(s)                     mol_slice_by_offset(s, 12, 1)
#define                                 MolReader_Auth_get_nth13(s)                     mol_slice_by_offset(s, 13, 1)
#define                                 MolReader_Auth_get_nth14(s)                     mol_slice_by_offset(s, 14, 1)
#define                                 MolReader_Auth_get_nth15(s)                     mol_slice_by_offset(s, 15, 1)
#define                                 MolReader_Auth_get_nth16(s)                     mol_slice_by_offset(s, 16, 1)
#define                                 MolReader_Auth_get_nth17(s)                     mol_slice_by_offset(s, 17, 1)
#define                                 MolReader_Auth_get_nth18(s)                     mol_slice_by_offset(s, 18, 1)
#define                                 MolReader_Auth_get_nth19(s)                     mol_slice_by_offset(s, 19, 1)
#define                                 MolReader_Auth_get_nth20(s)                     mol_slice_by_offset(s, 20, 1)
MOLECULE_API_DECORATOR  mol_errno       MolReader_Identity_verify                       (const mol_seg_t*, bool);
#define                                 MolReader_Identity_actual_field_count(s)        mol_table_actual_field_count(s)
#define                                 MolReader_Identity_has_extra_fields(s)          mol_table_has_extra_fields(s, 2)
#define                                 MolReader_Identity_get_identity(s)              mol_table_slice_by_index(s, 0)
#define                                 MolReader_Identity_get_proofs(s)                mol_table_slice_by_index(s, 1)
MOLECULE_API_DECORATOR  mol_errno       MolReader_IdentityOpt_verify                    (const mol_seg_t*, bool);
#define                                 MolReader_IdentityOpt_is_none(s)                mol_option_is_none(s)
MOLECULE_API_DECORATOR  mol_errno       MolReader_OmniLockWitnessLock_verify            (const mol_seg_t*, bool);
#define                                 MolReader_OmniLockWitnessLock_actual_field_count(s) mol_table_actual_field_count(s)
#define                                 MolReader_OmniLockWitnessLock_has_extra_fields(s) mol_table_has_extra_fields(s, 3)
#define                                 MolReader_OmniLockWitnessLock_get_signature(s)  mol_table_slice_by_index(s, 0)
#define                                 MolReader_OmniLockWitnessLock_get_omni_identity(s) mol_table_slice_by_index(s, 1)
#define                                 MolReader_OmniLockWitnessLock_get_preimage(s)   mol_table_slice_by_index(s, 2)

/*
 * Builder APIs
 */

#define                                 MolBuilder_Auth_init(b)                         mol_builder_initialize_fixed_size(b, 21)
#define                                 MolBuilder_Auth_set_nth0(b, p)                  mol_builder_set_byte_by_offset(b, 0, p)
#define                                 MolBuilder_Auth_set_nth1(b, p)                  mol_builder_set_byte_by_offset(b, 1, p)
#define                                 MolBuilder_Auth_set_nth2(b, p)                  mol_builder_set_byte_by_offset(b, 2, p)
#define                                 MolBuilder_Auth_set_nth3(b, p)                  mol_builder_set_byte_by_offset(b, 3, p)
#define                                 MolBuilder_Auth_set_nth4(b, p)                  mol_builder_set_byte_by_offset(b, 4, p)
#define                                 MolBuilder_Auth_set_nth5(b, p)                  mol_builder_set_byte_by_offset(b, 5, p)
#define                                 MolBuilder_Auth_set_nth6(b, p)                  mol_builder_set_byte_by_offset(b, 6, p)
#define                                 MolBuilder_Auth_set_nth7(b, p)                  mol_builder_set_byte_by_offset(b, 7, p)
#define                                 MolBuilder_Auth_set_nth8(b, p)                  mol_builder_set_byte_by_offset(b, 8, p)
#define                                 MolBuilder_Auth_set_nth9(b, p)                  mol_builder_set_byte_by_offset(b, 9, p)
#define                                 MolBuilder_Auth_set_nth10(b, p)                 mol_builder_set_byte_by_offset(b, 10, p)
#define                                 MolBuilder_Auth_set_nth11(b, p)                 mol_builder_set_byte_by_offset(b, 11, p)
#define                                 MolBuilder_Auth_set_nth12(b, p)                 mol_builder_set_byte_by_offset(b, 12, p)
#define                                 MolBuilder_Auth_set_nth13(b, p)                 mol_builder_set_byte_by_offset(b, 13, p)
#define                                 MolBuilder_Auth_set_nth14(b, p)                 mol_builder_set_byte_by_offset(b, 14, p)
#define                                 MolBuilder_Auth_set_nth15(b, p)                 mol_builder_set_byte_by_offset(b, 15, p)
#define                                 MolBuilder_Auth_set_nth16(b, p)                 mol_builder_set_byte_by_offset(b, 16, p)
#define                                 MolBuilder_Auth_set_nth17(b, p)                 mol_builder_set_byte_by_offset(b, 17, p)
#define                                 MolBuilder_Auth_set_nth18(b, p)                 mol_builder_set_byte_by_offset(b, 18, p)
#define                                 MolBuilder_Auth_set_nth19(b, p)                 mol_builder_set_byte_by_offset(b, 19, p)
#define                                 MolBuilder_Auth_set_nth20(b, p)                 mol_builder_set_byte_by_offset(b, 20, p)
#define                                 MolBuilder_Auth_build(b)                        mol_builder_finalize_simple(b)
#define                                 MolBuilder_Auth_clear(b)                        mol_builder_discard(b)
#define                                 MolBuilder_Identity_init(b)                     mol_table_builder_initialize(b, 256, 2)
#define                                 MolBuilder_Identity_set_identity(b, p, l)       mol_table_builder_add(b, 0, p, l)
#define                                 MolBuilder_Identity_set_proofs(b, p, l)         mol_table_builder_add(b, 1, p, l)
MOLECULE_API_DECORATOR  mol_seg_res_t   MolBuilder_Identity_build                       (mol_builder_t);
#define                                 MolBuilder_Identity_clear(b)                    mol_builder_discard(b)
#define                                 MolBuilder_IdentityOpt_init(b)                  mol_builder_initialize_fixed_size(b, 0)
#define                                 MolBuilder_IdentityOpt_set(b, p, l)             mol_option_builder_set(b, p, l)
#define                                 MolBuilder_IdentityOpt_build(b)                 mol_builder_finalize_simple(b)
#define                                 MolBuilder_IdentityOpt_clear(b)                 mol_builder_discard(b)
#define                                 MolBuilder_OmniLockWitnessLock_init(b)          mol_table_builder_initialize(b, 64, 3)
#define                                 MolBuilder_OmniLockWitnessLock_set_signature(b, p, l) mol_table_builder_add(b, 0, p, l)
#define                                 MolBuilder_OmniLockWitnessLock_set_omni_identity(b, p, l) mol_table_builder_add(b, 1, p, l)
#define                                 MolBuilder_OmniLockWitnessLock_set_preimage(b, p, l) mol_table_builder_add(b, 2, p, l)
MOLECULE_API_DECORATOR  mol_seg_res_t   MolBuilder_OmniLockWitnessLock_build            (mol_builder_t);
#define                                 MolBuilder_OmniLockWitnessLock_clear(b)         mol_builder_discard(b)

/*
 * Default Value
 */

#define ____ 0x00

MOLECULE_API_DECORATOR const uint8_t MolDefault_Auth[21]         =  {
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____,
};
MOLECULE_API_DECORATOR const uint8_t MolDefault_Identity[37]     =  {
    0x25, ____, ____, ____, 0x0c, ____, ____, ____, 0x21, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____, ____,
    ____, ____, ____, ____, ____, ____, ____, ____, ____, 0x04, ____, ____,
    ____,
};
MOLECULE_API_DECORATOR const uint8_t MolDefault_IdentityOpt[0]   =  {};
MOLECULE_API_DECORATOR const uint8_t MolDefault_OmniLockWitnessLock[16] =  {
    0x10, ____, ____, ____, 0x10, ____, ____, ____, 0x10, ____, ____, ____,
    0x10, ____, ____, ____,
};

#undef ____

/*
 * Reader Functions
 */

MOLECULE_API_DECORATOR mol_errno MolReader_Identity_verify (const mol_seg_t *input, bool compatible) {
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
        errno = MolReader_Auth_verify(&inner, compatible);
        if (errno != MOL_OK) {
            return MOL_ERR_DATA;
        }
        inner.ptr = input->ptr + offsets[1];
        inner.size = offsets[2] - offsets[1];
        errno = MolReader_SmtProofEntryVec_verify(&inner, compatible);
        if (errno != MOL_OK) {
            return MOL_ERR_DATA;
        }
    return MOL_OK;
}
MOLECULE_API_DECORATOR mol_errno MolReader_IdentityOpt_verify (const mol_seg_t *input, bool compatible) {
    if (input->size != 0) {
        return MolReader_Identity_verify(input, compatible);
    } else {
        return MOL_OK;
    }
}
MOLECULE_API_DECORATOR mol_errno MolReader_OmniLockWitnessLock_verify (const mol_seg_t *input, bool compatible) {
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
    if (field_count < 3) {
        return MOL_ERR_FIELD_COUNT;
    } else if (!compatible && field_count > 3) {
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
        errno = MolReader_BytesOpt_verify(&inner, compatible);
        if (errno != MOL_OK) {
            return MOL_ERR_DATA;
        }
        inner.ptr = input->ptr + offsets[1];
        inner.size = offsets[2] - offsets[1];
        errno = MolReader_IdentityOpt_verify(&inner, compatible);
        if (errno != MOL_OK) {
            return MOL_ERR_DATA;
        }
        inner.ptr = input->ptr + offsets[2];
        inner.size = offsets[3] - offsets[2];
        errno = MolReader_BytesOpt_verify(&inner, compatible);
        if (errno != MOL_OK) {
            return MOL_ERR_DATA;
        }
    return MOL_OK;
}

/*
 * Builder Functions
 */

MOLECULE_API_DECORATOR mol_seg_res_t MolBuilder_Identity_build (mol_builder_t builder) {
    mol_seg_res_t res;
    res.errno = MOL_OK;
    mol_num_t offset = 12;
    mol_num_t len;
    res.seg.size = offset;
    len = builder.number_ptr[1];
    res.seg.size += len == 0 ? 21 : len;
    len = builder.number_ptr[3];
    res.seg.size += len == 0 ? 4 : len;
    res.seg.ptr = (uint8_t*)malloc(res.seg.size);
    uint8_t *dst = res.seg.ptr;
    mol_pack_number(dst, &res.seg.size);
    dst += MOL_NUM_T_SIZE;
    mol_pack_number(dst, &offset);
    dst += MOL_NUM_T_SIZE;
    len = builder.number_ptr[1];
    offset += len == 0 ? 21 : len;
    mol_pack_number(dst, &offset);
    dst += MOL_NUM_T_SIZE;
    len = builder.number_ptr[3];
    offset += len == 0 ? 4 : len;
    uint8_t *src = builder.data_ptr;
    len = builder.number_ptr[1];
    if (len == 0) {
        len = 21;
        memcpy(dst, &MolDefault_Auth, len);
    } else {
        mol_num_t of = builder.number_ptr[0];
        memcpy(dst, src+of, len);
    }
    dst += len;
    len = builder.number_ptr[3];
    if (len == 0) {
        len = 4;
        memcpy(dst, &MolDefault_SmtProofEntryVec, len);
    } else {
        mol_num_t of = builder.number_ptr[2];
        memcpy(dst, src+of, len);
    }
    dst += len;
    mol_builder_discard(builder);
    return res;
}
MOLECULE_API_DECORATOR mol_seg_res_t MolBuilder_OmniLockWitnessLock_build (mol_builder_t builder) {
    mol_seg_res_t res;
    res.errno = MOL_OK;
    mol_num_t offset = 16;
    mol_num_t len;
    res.seg.size = offset;
    len = builder.number_ptr[1];
    res.seg.size += len == 0 ? 0 : len;
    len = builder.number_ptr[3];
    res.seg.size += len == 0 ? 0 : len;
    len = builder.number_ptr[5];
    res.seg.size += len == 0 ? 0 : len;
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
    offset += len == 0 ? 0 : len;
    mol_pack_number(dst, &offset);
    dst += MOL_NUM_T_SIZE;
    len = builder.number_ptr[5];
    offset += len == 0 ? 0 : len;
    uint8_t *src = builder.data_ptr;
    len = builder.number_ptr[1];
    if (len == 0) {
        len = 0;
        memcpy(dst, &MolDefault_BytesOpt, len);
    } else {
        mol_num_t of = builder.number_ptr[0];
        memcpy(dst, src+of, len);
    }
    dst += len;
    len = builder.number_ptr[3];
    if (len == 0) {
        len = 0;
        memcpy(dst, &MolDefault_IdentityOpt, len);
    } else {
        mol_num_t of = builder.number_ptr[2];
        memcpy(dst, src+of, len);
    }
    dst += len;
    len = builder.number_ptr[5];
    if (len == 0) {
        len = 0;
        memcpy(dst, &MolDefault_BytesOpt, len);
    } else {
        mol_num_t of = builder.number_ptr[4];
        memcpy(dst, src+of, len);
    }
    dst += len;
    mol_builder_discard(builder);
    return res;
}

#ifdef __DEFINE_MOLECULE_API_DECORATOR_RC_LOCK
#undef MOLECULE_API_DECORATOR
#undef __DEFINE_MOLECULE_API_DECORATOR_RC_LOCK
#endif /* __DEFINE_MOLECULE_API_DECORATOR_RC_LOCK */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* RC_LOCK_H */
