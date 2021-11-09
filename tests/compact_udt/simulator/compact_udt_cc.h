

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stdint.h>
#include "compact_udt_lock_inc.h"

enum _CompactUDTMolType {
  CUDTMOLType_Scritp,
  CUDTMOLType_CellData,
  CUDTMOLType_Witness,
};
typedef uint8_t CompactUDTMolType;

typedef struct _CUDTMOL_Data {
  CompactUDTMolType type;
  size_t index;
  size_t source;
  bool index_out_of_bound;

  size_t field;
  bool by_field;

  uint8_t* out_ptr;
  uint32_t out_len;
  bool out_need_free;

} CUDTMOL_Data;

bool cc_get_data(CUDTMOL_Data* param);
uint32_t cc_get_input_len();

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#ifdef __cplusplus

#include "util/util.h"

#endif  // __cplusplus
