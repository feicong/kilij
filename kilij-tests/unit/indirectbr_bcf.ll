; Unit test: indirectbr terminators exist in real IR (computed goto,
; blockaddress). CFG-mutating passes should skip indirectbr blocks and still
; never produce invalid IR.

source_filename = "indirectbr_bcf.ll"

define i32 @indirectbr_bcf() {
entry:
  indirectbr ptr blockaddress(@indirectbr_bcf, %bb1), [label %bb1, label %bb2]

bb1:
  ret i32 1

bb2:
  ret i32 2
}
