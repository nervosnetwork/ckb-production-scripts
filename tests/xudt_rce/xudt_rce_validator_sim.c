#if defined(CKB_COVERAGE)
#define ASSERT(s) (void)0
#else
#define ASSERT(s) (void)0
#endif

int ckb_exit(signed char code);

#include "rce_validator.c"
#include "utest.h"

// make compiler happy
int make_cursor_from_witness(WitnessArgsType *witness) {
  ASSERT(false);
  return 0;
}

// reset all status
void rce_validator_init() {
  g_sim_rcdata_count[0] = 0;
  g_sim_rcdata_count[1] = 0;
  g_script_flags = 0;
  g_cell_group_exists[0][0] = 1;
  g_cell_group_exists[1][0] = 1;
}

UTEST(rce_validator, bl_append_key) {
  rce_validator_init();
  int err = 0;

  SIMRCData *curr_0 = g_sim_rcdata[0] + g_sim_rcdata_count[0];
  curr_0->rcrule.id = 0;
  curr_0->rcrule.flags = 0;
  memcpy(curr_0->rcrule.smt_root, smt_one_root, countof(smt_one_root));
  g_sim_rcdata_count[0] += 1;

  SIMRCData *curr_1 = g_sim_rcdata[1] + g_sim_rcdata_count[1];
  curr_1->rcrule.id = 0;
  curr_1->rcrule.flags = 0;
  memcpy(curr_1->rcrule.smt_root, smt_two_root, countof(smt_two_root));
  g_sim_rcdata_count[1] += 1;

  uint8_t update_key[32];
  uint8_t update_packed_value = (0 << 4) | 1;
  uint8_t update_proof_bytes[countof(smt_one_not_k2_proof)];
  memcpy(update_key, k2, 32);
  memcpy(update_proof_bytes, smt_one_not_k2_proof,
         countof(smt_one_not_k2_proof));
  mol_seg_t update_proof =
      build_bytes(update_proof_bytes, countof(smt_one_not_k2_proof));

  mol_builder_t update_item_builer;
  MolBuilder_SmtUpdateItem_init(&update_item_builer);
  MolBuilder_SmtUpdateItem_set_key(&update_item_builer, update_key);
  MolBuilder_SmtUpdateItem_set_packed_values(&update_item_builer,
                                             update_packed_value);
  mol_seg_res_t update_item_res =
      MolBuilder_SmtUpdateItem_build(update_item_builer);
  mol_seg_t update_item = update_item_res.seg;

  mol_builder_t update_item_vec_builder;
  MolBuilder_SmtUpdateItemVec_init(&update_item_vec_builder);
  MolBuilder_SmtUpdateItemVec_push(&update_item_vec_builder, update_item.ptr);
  mol_seg_res_t update_item_vec_res =
      MolBuilder_SmtUpdateItemVec_build(update_item_vec_builder);
  mol_seg_t update_item_vec = update_item_vec_res.seg;

  mol_builder_t update_action_builder;
  MolBuilder_SmtUpdateAction_init(&update_action_builder);
  MolBuilder_SmtUpdateAction_set_updates(
      &update_action_builder, update_item_vec.ptr, update_item_vec.size);
  MolBuilder_SmtUpdateAction_set_proof(&update_action_builder, update_proof.ptr,
                                       update_proof.size);
  mol_seg_res_t update_action_res =
      MolBuilder_SmtUpdateAction_build(update_action_builder);
  mol_seg_t update_action =
      build_bytes(update_action_res.seg.ptr, update_action_res.seg.size);

  mol_builder_t witness_args_builder;
  MolBuilder_WitnessArgs_init(&witness_args_builder);
  MolBuilder_WitnessArgs_set_input_type(&witness_args_builder,
                                        update_action.ptr, update_action.size);
  uint8_t dummy_lock[4096] = {0};
  mol_seg_t lock = build_bytes(dummy_lock, sizeof(dummy_lock));
  MolBuilder_WitnessArgs_set_lock(&witness_args_builder, lock.ptr, lock.size);
  mol_seg_res_t witness_args_res =
      MolBuilder_WitnessArgs_build(witness_args_builder);
  mol_seg_t witness_args = witness_args_res.seg;

  g_witness_size = witness_args.size;
  memcpy(g_witness, witness_args.ptr, g_witness_size);

  err = simulator_main();

exit:
  ASSERT_EQ(err, 0);
}

UTEST(rce_validator, bl_append_key_with_freeze_type) {
  rce_validator_init();
  g_script_flags = 0x2;
  int err = 0;

  SIMRCData *curr_0 = g_sim_rcdata[0] + g_sim_rcdata_count[0];
  curr_0->rcrule.id = 0;
  curr_0->rcrule.flags = 0;
  memcpy(curr_0->rcrule.smt_root, smt_one_root, countof(smt_one_root));
  g_sim_rcdata_count[0] += 1;

  SIMRCData *curr_1 = g_sim_rcdata[1] + g_sim_rcdata_count[1];
  curr_1->rcrule.id = 0;
  curr_1->rcrule.flags = 0;
  memcpy(curr_1->rcrule.smt_root, smt_two_root, countof(smt_two_root));
  g_sim_rcdata_count[1] += 1;

  uint8_t update_key[32];
  uint8_t update_packed_value = (0 << 4) | 1;
  uint8_t update_proof_bytes[countof(smt_one_not_k2_proof)];
  memcpy(update_key, k2, 32);
  memcpy(update_proof_bytes, smt_one_not_k2_proof,
         countof(smt_one_not_k2_proof));
  mol_seg_t update_proof =
      build_bytes(update_proof_bytes, countof(smt_one_not_k2_proof));

  mol_builder_t update_item_builer;
  MolBuilder_SmtUpdateItem_init(&update_item_builer);
  MolBuilder_SmtUpdateItem_set_key(&update_item_builer, update_key);
  MolBuilder_SmtUpdateItem_set_packed_values(&update_item_builer,
                                             update_packed_value);
  mol_seg_res_t update_item_res =
      MolBuilder_SmtUpdateItem_build(update_item_builer);
  mol_seg_t update_item = update_item_res.seg;

  mol_builder_t update_item_vec_builder;
  MolBuilder_SmtUpdateItemVec_init(&update_item_vec_builder);
  MolBuilder_SmtUpdateItemVec_push(&update_item_vec_builder, update_item.ptr);
  mol_seg_res_t update_item_vec_res =
      MolBuilder_SmtUpdateItemVec_build(update_item_vec_builder);
  mol_seg_t update_item_vec = update_item_vec_res.seg;

  mol_builder_t update_action_builder;
  MolBuilder_SmtUpdateAction_init(&update_action_builder);
  MolBuilder_SmtUpdateAction_set_updates(
      &update_action_builder, update_item_vec.ptr, update_item_vec.size);
  MolBuilder_SmtUpdateAction_set_proof(&update_action_builder, update_proof.ptr,
                                       update_proof.size);
  mol_seg_res_t update_action_res =
      MolBuilder_SmtUpdateAction_build(update_action_builder);
  mol_seg_t update_action =
      build_bytes(update_action_res.seg.ptr, update_action_res.seg.size);

  mol_builder_t witness_args_builder;
  MolBuilder_WitnessArgs_init(&witness_args_builder);
  MolBuilder_WitnessArgs_set_input_type(&witness_args_builder,
                                        update_action.ptr, update_action.size);
  uint8_t dummy_lock[4096] = {0};
  mol_seg_t lock = build_bytes(dummy_lock, sizeof(dummy_lock));
  MolBuilder_WitnessArgs_set_lock(&witness_args_builder, lock.ptr, lock.size);
  mol_seg_res_t witness_args_res =
      MolBuilder_WitnessArgs_build(witness_args_builder);
  mol_seg_t witness_args = witness_args_res.seg;

  g_witness_size = witness_args.size;
  memcpy(g_witness, witness_args.ptr, g_witness_size);

  err = simulator_main();

exit:
  ASSERT_EQ(err, 0);
}

UTEST(rce_validator, bl_remove_key) {
  rce_validator_init();
  int err = 0;

  SIMRCData *curr_0 = g_sim_rcdata[0] + g_sim_rcdata_count[0];
  curr_0->rcrule.id = 0;
  curr_0->rcrule.flags = 0;
  memcpy(curr_0->rcrule.smt_root, smt_two_root, countof(smt_two_root));
  g_sim_rcdata_count[0] += 1;

  SIMRCData *curr_1 = g_sim_rcdata[1] + g_sim_rcdata_count[1];
  curr_1->rcrule.id = 0;
  curr_1->rcrule.flags = 0;
  memcpy(curr_1->rcrule.smt_root, smt_one_root, countof(smt_one_root));
  g_sim_rcdata_count[1] += 1;

  uint8_t update_key[32];
  uint8_t update_packed_value = (1 << 4) | 0;
  uint8_t update_proof_bytes[countof(smt_tow_has_k2_proof)];
  memcpy(update_key, k2, 32);
  memcpy(update_proof_bytes, smt_tow_has_k2_proof,
         countof(smt_tow_has_k2_proof));
  mol_seg_t update_proof =
      build_bytes(update_proof_bytes, countof(smt_tow_has_k2_proof));

  mol_builder_t update_item_builer;
  MolBuilder_SmtUpdateItem_init(&update_item_builer);
  MolBuilder_SmtUpdateItem_set_key(&update_item_builer, update_key);
  MolBuilder_SmtUpdateItem_set_packed_values(&update_item_builer,
                                             update_packed_value);
  mol_seg_res_t update_item_res =
      MolBuilder_SmtUpdateItem_build(update_item_builer);
  mol_seg_t update_item = update_item_res.seg;

  mol_builder_t update_item_vec_builder;
  MolBuilder_SmtUpdateItemVec_init(&update_item_vec_builder);
  MolBuilder_SmtUpdateItemVec_push(&update_item_vec_builder, update_item.ptr);
  mol_seg_res_t update_item_vec_res =
      MolBuilder_SmtUpdateItemVec_build(update_item_vec_builder);
  mol_seg_t update_item_vec = update_item_vec_res.seg;

  mol_builder_t update_action_builder;
  MolBuilder_SmtUpdateAction_init(&update_action_builder);
  MolBuilder_SmtUpdateAction_set_updates(
      &update_action_builder, update_item_vec.ptr, update_item_vec.size);
  MolBuilder_SmtUpdateAction_set_proof(&update_action_builder, update_proof.ptr,
                                       update_proof.size);
  mol_seg_res_t update_action_res =
      MolBuilder_SmtUpdateAction_build(update_action_builder);
  mol_seg_t update_action =
      build_bytes(update_action_res.seg.ptr, update_action_res.seg.size);

  mol_builder_t witness_args_builder;
  MolBuilder_WitnessArgs_init(&witness_args_builder);
  MolBuilder_WitnessArgs_set_input_type(&witness_args_builder,
                                        update_action.ptr, update_action.size);
  uint8_t dummy_lock[4096] = {0};
  mol_seg_t lock = build_bytes(dummy_lock, sizeof(dummy_lock));
  MolBuilder_WitnessArgs_set_lock(&witness_args_builder, lock.ptr, lock.size);
  mol_seg_res_t witness_args_res =
      MolBuilder_WitnessArgs_build(witness_args_builder);
  mol_seg_t witness_args = witness_args_res.seg;

  g_witness_size = witness_args.size;
  memcpy(g_witness, witness_args.ptr, g_witness_size);

  err = simulator_main();

exit:
  ASSERT_EQ(err, 0);
}

UTEST(rce_validator, bl_remove_key_but_append_only) {
  rce_validator_init();
  g_script_flags = 1;

  int err = 0;

  SIMRCData *curr_0 = g_sim_rcdata[0] + g_sim_rcdata_count[0];
  curr_0->rcrule.id = 0;
  curr_0->rcrule.flags = 0;
  memcpy(curr_0->rcrule.smt_root, smt_two_root, countof(smt_two_root));
  g_sim_rcdata_count[0] += 1;

  SIMRCData *curr_1 = g_sim_rcdata[1] + g_sim_rcdata_count[1];
  curr_1->rcrule.id = 0;
  curr_1->rcrule.flags = 0;
  memcpy(curr_1->rcrule.smt_root, smt_one_root, countof(smt_one_root));
  g_sim_rcdata_count[1] += 1;

  uint8_t update_key[32];
  uint8_t update_packed_value = (1 << 4) | 0;
  uint8_t update_proof_bytes[countof(smt_tow_has_k2_proof)];
  memcpy(update_key, k2, 32);
  memcpy(update_proof_bytes, smt_tow_has_k2_proof,
         countof(smt_tow_has_k2_proof));
  mol_seg_t update_proof =
      build_bytes(update_proof_bytes, countof(smt_tow_has_k2_proof));

  mol_builder_t update_item_builer;
  MolBuilder_SmtUpdateItem_init(&update_item_builer);
  MolBuilder_SmtUpdateItem_set_key(&update_item_builer, update_key);
  MolBuilder_SmtUpdateItem_set_packed_values(&update_item_builer,
                                             update_packed_value);
  mol_seg_res_t update_item_res =
      MolBuilder_SmtUpdateItem_build(update_item_builer);
  mol_seg_t update_item = update_item_res.seg;

  mol_builder_t update_item_vec_builder;
  MolBuilder_SmtUpdateItemVec_init(&update_item_vec_builder);
  MolBuilder_SmtUpdateItemVec_push(&update_item_vec_builder, update_item.ptr);
  mol_seg_res_t update_item_vec_res =
      MolBuilder_SmtUpdateItemVec_build(update_item_vec_builder);
  mol_seg_t update_item_vec = update_item_vec_res.seg;

  mol_builder_t update_action_builder;
  MolBuilder_SmtUpdateAction_init(&update_action_builder);
  MolBuilder_SmtUpdateAction_set_updates(
      &update_action_builder, update_item_vec.ptr, update_item_vec.size);
  MolBuilder_SmtUpdateAction_set_proof(&update_action_builder, update_proof.ptr,
                                       update_proof.size);
  mol_seg_res_t update_action_res =
      MolBuilder_SmtUpdateAction_build(update_action_builder);
  mol_seg_t update_action =
      build_bytes(update_action_res.seg.ptr, update_action_res.seg.size);

  mol_builder_t witness_args_builder;
  MolBuilder_WitnessArgs_init(&witness_args_builder);
  MolBuilder_WitnessArgs_set_input_type(&witness_args_builder,
                                        update_action.ptr, update_action.size);
  uint8_t dummy_lock[4096] = {0};
  mol_seg_t lock = build_bytes(dummy_lock, sizeof(dummy_lock));
  MolBuilder_WitnessArgs_set_lock(&witness_args_builder, lock.ptr, lock.size);
  mol_seg_res_t witness_args_res =
      MolBuilder_WitnessArgs_build(witness_args_builder);
  mol_seg_t witness_args = witness_args_res.seg;

  g_witness_size = witness_args.size;
  memcpy(g_witness, witness_args.ptr, g_witness_size);

  err = simulator_main();

exit:
  ASSERT_EQ(err, ERROR_APPEND_ONLY);
}

UTEST(rce_validator, no_input) {
  rce_validator_init();
  g_cell_group_exists[0][0] = 0;
  int err = 0;

  SIMRCData *curr_1 = g_sim_rcdata[1] + g_sim_rcdata_count[1];
  curr_1->rcrule.id = 0;
  curr_1->rcrule.flags = 0;
  memcpy(curr_1->rcrule.smt_root, smt_one_root, countof(smt_one_root));
  g_sim_rcdata_count[1] += 1;

  uint8_t update_key[32];
  uint8_t update_packed_value = (0 << 4) | 1;
  uint8_t update_proof_bytes[countof(smt_ooo_not_k1_proof)];
  memcpy(update_key, k1, 32);
  memcpy(update_proof_bytes, smt_ooo_not_k1_proof,
         countof(smt_ooo_not_k1_proof));
  mol_seg_t update_proof =
      build_bytes(update_proof_bytes, countof(smt_ooo_not_k1_proof));

  mol_builder_t update_item_builer;
  MolBuilder_SmtUpdateItem_init(&update_item_builer);
  MolBuilder_SmtUpdateItem_set_key(&update_item_builer, update_key);
  MolBuilder_SmtUpdateItem_set_packed_values(&update_item_builer,
                                             update_packed_value);
  mol_seg_res_t update_item_res =
      MolBuilder_SmtUpdateItem_build(update_item_builer);
  mol_seg_t update_item = update_item_res.seg;

  mol_builder_t update_item_vec_builder;
  MolBuilder_SmtUpdateItemVec_init(&update_item_vec_builder);
  MolBuilder_SmtUpdateItemVec_push(&update_item_vec_builder, update_item.ptr);
  mol_seg_res_t update_item_vec_res =
      MolBuilder_SmtUpdateItemVec_build(update_item_vec_builder);
  mol_seg_t update_item_vec = update_item_vec_res.seg;

  mol_builder_t update_action_builder;
  MolBuilder_SmtUpdateAction_init(&update_action_builder);
  MolBuilder_SmtUpdateAction_set_updates(
      &update_action_builder, update_item_vec.ptr, update_item_vec.size);
  MolBuilder_SmtUpdateAction_set_proof(&update_action_builder, update_proof.ptr,
                                       update_proof.size);
  mol_seg_res_t update_action_res =
      MolBuilder_SmtUpdateAction_build(update_action_builder);
  mol_seg_t update_action =
      build_bytes(update_action_res.seg.ptr, update_action_res.seg.size);

  mol_builder_t witness_args_builder;
  MolBuilder_WitnessArgs_init(&witness_args_builder);
  MolBuilder_WitnessArgs_set_input_type(&witness_args_builder,
                                        update_action.ptr, update_action.size);
  uint8_t dummy_lock[4096] = {0};
  mol_seg_t lock = build_bytes(dummy_lock, sizeof(dummy_lock));
  MolBuilder_WitnessArgs_set_lock(&witness_args_builder, lock.ptr, lock.size);
  mol_seg_res_t witness_args_res =
      MolBuilder_WitnessArgs_build(witness_args_builder);
  mol_seg_t witness_args = witness_args_res.seg;

  g_witness_size = witness_args.size;
  memcpy(g_witness, witness_args.ptr, g_witness_size);

  err = simulator_main();

exit:
  ASSERT_EQ(err, 0);
}

UTEST(rce_validator, rccellvec_to_rccell) {
  rce_validator_init();
  int err = 0;

  SIMRCData *curr_0 = g_sim_rcdata[0] + g_sim_rcdata_count[0];
  curr_0->rccell_vec.id = 1;
  curr_0->rccell_vec.hash_count = 0;
  memset(curr_0->rccell_vec.hash, 0, 32);
  g_sim_rcdata_count[0] += 1;

  SIMRCData *curr_1 = g_sim_rcdata[1] + g_sim_rcdata_count[1];
  curr_1->rcrule.id = 0;
  curr_1->rcrule.flags = 0;
  memcpy(curr_1->rcrule.smt_root, smt_one_root, countof(smt_one_root));
  g_sim_rcdata_count[1] += 1;

  uint8_t update_key[32];
  uint8_t update_packed_value = (0 << 4) | 1;
  uint8_t update_proof_bytes[countof(smt_ooo_not_k1_proof)];
  memcpy(update_key, k1, 32);
  memcpy(update_proof_bytes, smt_ooo_not_k1_proof,
         countof(smt_ooo_not_k1_proof));
  mol_seg_t update_proof =
      build_bytes(update_proof_bytes, countof(smt_ooo_not_k1_proof));

  mol_builder_t update_item_builer;
  MolBuilder_SmtUpdateItem_init(&update_item_builer);
  MolBuilder_SmtUpdateItem_set_key(&update_item_builer, update_key);
  MolBuilder_SmtUpdateItem_set_packed_values(&update_item_builer,
                                             update_packed_value);
  mol_seg_res_t update_item_res =
      MolBuilder_SmtUpdateItem_build(update_item_builer);
  mol_seg_t update_item = update_item_res.seg;

  mol_builder_t update_item_vec_builder;
  MolBuilder_SmtUpdateItemVec_init(&update_item_vec_builder);
  MolBuilder_SmtUpdateItemVec_push(&update_item_vec_builder, update_item.ptr);
  mol_seg_res_t update_item_vec_res =
      MolBuilder_SmtUpdateItemVec_build(update_item_vec_builder);
  mol_seg_t update_item_vec = update_item_vec_res.seg;

  mol_builder_t update_action_builder;
  MolBuilder_SmtUpdateAction_init(&update_action_builder);
  MolBuilder_SmtUpdateAction_set_updates(
      &update_action_builder, update_item_vec.ptr, update_item_vec.size);
  MolBuilder_SmtUpdateAction_set_proof(&update_action_builder, update_proof.ptr,
                                       update_proof.size);
  mol_seg_res_t update_action_res =
      MolBuilder_SmtUpdateAction_build(update_action_builder);
  mol_seg_t update_action =
      build_bytes(update_action_res.seg.ptr, update_action_res.seg.size);

  mol_builder_t witness_args_builder;
  MolBuilder_WitnessArgs_init(&witness_args_builder);
  MolBuilder_WitnessArgs_set_input_type(&witness_args_builder,
                                        update_action.ptr, update_action.size);
  uint8_t dummy_lock[4096] = {0};
  mol_seg_t lock = build_bytes(dummy_lock, sizeof(dummy_lock));
  MolBuilder_WitnessArgs_set_lock(&witness_args_builder, lock.ptr, lock.size);
  mol_seg_res_t witness_args_res =
      MolBuilder_WitnessArgs_build(witness_args_builder);
  mol_seg_t witness_args = witness_args_res.seg;

  g_witness_size = witness_args.size;
  memcpy(g_witness, witness_args.ptr, g_witness_size);

  err = simulator_main();

exit:
  ASSERT_EQ(err, 0);
}

UTEST(rce_validator, rccellvec_to_rcrule_with_freeze_type) {
  rce_validator_init();
  g_script_flags = 0x2;
  int err = 0;

  SIMRCData *curr_0 = g_sim_rcdata[0] + g_sim_rcdata_count[0];
  curr_0->rccell_vec.id = 1;
  curr_0->rccell_vec.hash_count = 0;
  memset(curr_0->rccell_vec.hash, 0, 32);
  g_sim_rcdata_count[0] += 1;

  SIMRCData *curr_1 = g_sim_rcdata[1] + g_sim_rcdata_count[1];
  curr_1->rcrule.id = 0;
  curr_1->rcrule.flags = 0;
  memcpy(curr_1->rcrule.smt_root, smt_one_root, countof(smt_one_root));
  g_sim_rcdata_count[1] += 1;

  uint8_t update_key[32];
  uint8_t update_packed_value = (0 << 4) | 1;
  uint8_t update_proof_bytes[countof(smt_one_not_k2_proof)];
  memcpy(update_key, k2, 32);
  memcpy(update_proof_bytes, smt_one_not_k2_proof,
         countof(smt_one_not_k2_proof));
  mol_seg_t update_proof =
      build_bytes(update_proof_bytes, countof(smt_one_not_k2_proof));

  mol_builder_t update_item_builer;
  MolBuilder_SmtUpdateItem_init(&update_item_builer);
  MolBuilder_SmtUpdateItem_set_key(&update_item_builer, update_key);
  MolBuilder_SmtUpdateItem_set_packed_values(&update_item_builer,
                                             update_packed_value);
  mol_seg_res_t update_item_res =
      MolBuilder_SmtUpdateItem_build(update_item_builer);
  mol_seg_t update_item = update_item_res.seg;

  mol_builder_t update_item_vec_builder;
  MolBuilder_SmtUpdateItemVec_init(&update_item_vec_builder);
  MolBuilder_SmtUpdateItemVec_push(&update_item_vec_builder, update_item.ptr);
  mol_seg_res_t update_item_vec_res =
      MolBuilder_SmtUpdateItemVec_build(update_item_vec_builder);
  mol_seg_t update_item_vec = update_item_vec_res.seg;

  mol_builder_t update_action_builder;
  MolBuilder_SmtUpdateAction_init(&update_action_builder);
  MolBuilder_SmtUpdateAction_set_updates(
      &update_action_builder, update_item_vec.ptr, update_item_vec.size);
  MolBuilder_SmtUpdateAction_set_proof(&update_action_builder, update_proof.ptr,
                                       update_proof.size);
  mol_seg_res_t update_action_res =
      MolBuilder_SmtUpdateAction_build(update_action_builder);
  mol_seg_t update_action =
      build_bytes(update_action_res.seg.ptr, update_action_res.seg.size);

  mol_builder_t witness_args_builder;
  MolBuilder_WitnessArgs_init(&witness_args_builder);
  MolBuilder_WitnessArgs_set_input_type(&witness_args_builder,
                                        update_action.ptr, update_action.size);
  uint8_t dummy_lock[4096] = {0};
  mol_seg_t lock = build_bytes(dummy_lock, sizeof(dummy_lock));
  MolBuilder_WitnessArgs_set_lock(&witness_args_builder, lock.ptr, lock.size);
  mol_seg_res_t witness_args_res =
      MolBuilder_WitnessArgs_build(witness_args_builder);
  mol_seg_t witness_args = witness_args_res.seg;

  g_witness_size = witness_args.size;
  memcpy(g_witness, witness_args.ptr, g_witness_size);

  err = simulator_main();

exit:
  ASSERT_EQ(err, ERROR_TYPE_FREEZED);
}

UTEST(rce_validator, rcrule_to_rccellvec_with_freeze_type) {
  rce_validator_init();
  g_script_flags = 0x2;
  int err = 0;

  SIMRCData *curr_0 = g_sim_rcdata[1] + g_sim_rcdata_count[1];
  curr_0->rcrule.id = 0;
  curr_0->rcrule.flags = 0;
  memcpy(curr_0->rcrule.smt_root, smt_one_root, countof(smt_one_root));
  g_sim_rcdata_count[0] += 1;

  SIMRCData *curr_1 = g_sim_rcdata[0] + g_sim_rcdata_count[0];
  curr_1->rccell_vec.id = 1;
  curr_1->rccell_vec.hash_count = 0;
  memset(curr_1->rccell_vec.hash, 0, 32);
  g_sim_rcdata_count[1] += 1;

  uint8_t update_key[32];
  uint8_t update_packed_value = (1 << 4) | 0;
  uint8_t update_proof_bytes[countof(smt_one_has_k1_proof)];
  memcpy(update_key, k1, 32);
  memcpy(update_proof_bytes, smt_one_has_k1_proof,
         countof(smt_one_has_k1_proof));
  mol_seg_t update_proof =
      build_bytes(update_proof_bytes, countof(smt_one_has_k1_proof));

  mol_builder_t update_item_builer;
  MolBuilder_SmtUpdateItem_init(&update_item_builer);
  MolBuilder_SmtUpdateItem_set_key(&update_item_builer, update_key);
  MolBuilder_SmtUpdateItem_set_packed_values(&update_item_builer,
                                             update_packed_value);
  mol_seg_res_t update_item_res =
      MolBuilder_SmtUpdateItem_build(update_item_builer);
  mol_seg_t update_item = update_item_res.seg;

  mol_builder_t update_item_vec_builder;
  MolBuilder_SmtUpdateItemVec_init(&update_item_vec_builder);
  MolBuilder_SmtUpdateItemVec_push(&update_item_vec_builder, update_item.ptr);
  mol_seg_res_t update_item_vec_res =
      MolBuilder_SmtUpdateItemVec_build(update_item_vec_builder);
  mol_seg_t update_item_vec = update_item_vec_res.seg;

  mol_builder_t update_action_builder;
  MolBuilder_SmtUpdateAction_init(&update_action_builder);
  MolBuilder_SmtUpdateAction_set_updates(
      &update_action_builder, update_item_vec.ptr, update_item_vec.size);
  MolBuilder_SmtUpdateAction_set_proof(&update_action_builder, update_proof.ptr,
                                       update_proof.size);
  mol_seg_res_t update_action_res =
      MolBuilder_SmtUpdateAction_build(update_action_builder);
  mol_seg_t update_action =
      build_bytes(update_action_res.seg.ptr, update_action_res.seg.size);

  mol_builder_t witness_args_builder;
  MolBuilder_WitnessArgs_init(&witness_args_builder);
  MolBuilder_WitnessArgs_set_input_type(&witness_args_builder,
                                        update_action.ptr, update_action.size);
  uint8_t dummy_lock[4096] = {0};
  mol_seg_t lock = build_bytes(dummy_lock, sizeof(dummy_lock));
  MolBuilder_WitnessArgs_set_lock(&witness_args_builder, lock.ptr, lock.size);
  mol_seg_res_t witness_args_res =
      MolBuilder_WitnessArgs_build(witness_args_builder);
  mol_seg_t witness_args = witness_args_res.seg;

  g_witness_size = witness_args.size;
  memcpy(g_witness, witness_args.ptr, g_witness_size);

  err = simulator_main();

exit:
  ASSERT_EQ(err, ERROR_TYPE_FREEZED);
}

UTEST(rce_validator, bl_update_to_wl) {
  rce_validator_init();
  int err = 0;

  SIMRCData *curr_0 = g_sim_rcdata[0] + g_sim_rcdata_count[0];
  curr_0->rcrule.id = 0;
  curr_0->rcrule.flags = 0;
  memcpy(curr_0->rcrule.smt_root, smt_one_root, countof(smt_one_root));
  g_sim_rcdata_count[0] += 1;

  SIMRCData *curr_1 = g_sim_rcdata[1] + g_sim_rcdata_count[1];
  curr_1->rcrule.id = 0;
  curr_1->rcrule.flags = 1;
  memcpy(curr_1->rcrule.smt_root, smt_two_root, countof(smt_two_root));
  g_sim_rcdata_count[1] += 1;

  uint8_t update_key[32];
  uint8_t update_packed_value = (0 << 4) | 1;
  uint8_t update_proof_bytes[countof(smt_one_not_k2_proof)];
  memcpy(update_key, k2, 32);
  memcpy(update_proof_bytes, smt_one_not_k2_proof,
         countof(smt_one_not_k2_proof));
  mol_seg_t update_proof =
      build_bytes(update_proof_bytes, countof(smt_one_not_k2_proof));

  mol_builder_t update_item_builer;
  MolBuilder_SmtUpdateItem_init(&update_item_builer);
  MolBuilder_SmtUpdateItem_set_key(&update_item_builer, update_key);
  MolBuilder_SmtUpdateItem_set_packed_values(&update_item_builer,
                                             update_packed_value);
  mol_seg_res_t update_item_res =
      MolBuilder_SmtUpdateItem_build(update_item_builer);
  mol_seg_t update_item = update_item_res.seg;

  mol_builder_t update_item_vec_builder;
  MolBuilder_SmtUpdateItemVec_init(&update_item_vec_builder);
  MolBuilder_SmtUpdateItemVec_push(&update_item_vec_builder, update_item.ptr);
  mol_seg_res_t update_item_vec_res =
      MolBuilder_SmtUpdateItemVec_build(update_item_vec_builder);
  mol_seg_t update_item_vec = update_item_vec_res.seg;

  mol_builder_t update_action_builder;
  MolBuilder_SmtUpdateAction_init(&update_action_builder);
  MolBuilder_SmtUpdateAction_set_updates(
      &update_action_builder, update_item_vec.ptr, update_item_vec.size);
  MolBuilder_SmtUpdateAction_set_proof(&update_action_builder, update_proof.ptr,
                                       update_proof.size);
  mol_seg_res_t update_action_res =
      MolBuilder_SmtUpdateAction_build(update_action_builder);
  mol_seg_t update_action =
      build_bytes(update_action_res.seg.ptr, update_action_res.seg.size);

  mol_builder_t witness_args_builder;
  MolBuilder_WitnessArgs_init(&witness_args_builder);
  MolBuilder_WitnessArgs_set_input_type(&witness_args_builder,
                                        update_action.ptr, update_action.size);
  uint8_t dummy_lock[4096] = {0};
  mol_seg_t lock = build_bytes(dummy_lock, sizeof(dummy_lock));
  MolBuilder_WitnessArgs_set_lock(&witness_args_builder, lock.ptr, lock.size);
  mol_seg_res_t witness_args_res =
      MolBuilder_WitnessArgs_build(witness_args_builder);
  mol_seg_t witness_args = witness_args_res.seg;

  g_witness_size = witness_args.size;
  memcpy(g_witness, witness_args.ptr, g_witness_size);

  err = simulator_main();

exit:
  ASSERT_EQ(err, 0);
}

UTEST_MAIN();
