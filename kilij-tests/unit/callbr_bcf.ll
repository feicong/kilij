; Unit test: callbr terminators exist in real IR (asm goto). CFG-mutating
; passes should skip callbr blocks and still never produce invalid IR.

source_filename = "callbr_bcf.ll"

define void @callbr_bcf(i32 %input) {
entry:
  callbr void asm "nop", "r,!i"(i32 %input) to label %bb_01 [label %bb_02]

bb_01:
  ret void

bb_02:
  ret void
}

