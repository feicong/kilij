; Minimal IR with a musttail call. CFG-mutating passes must not split between
; the musttail call and its return (verifier failure otherwise).

target triple = "x86_64-pc-windows-msvc"

declare i32 @callee(i32)

define dso_local i32 @caller(i32 %x) {
entry:
  %r = musttail call i32 @callee(i32 %x)
  ret i32 %r
}

