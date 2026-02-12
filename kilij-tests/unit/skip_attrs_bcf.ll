; Unit test: custom function attributes ("no_obfuscate"/"obf_skip") must
; override enabled obfuscation passes.

source_filename = "skip_attrs_bcf.ll"

define i32 @bcf_ok(i32 %x) {
entry:
  %a = add i32 %x, 1
  %b = mul i32 %a, 3
  ret i32 %b
}

define i32 @bcf_no_obfuscate(i32 %x) #0 {
entry:
  %a = add i32 %x, 1
  %b = mul i32 %a, 3
  ret i32 %b
}

define i32 @bcf_obf_skip(i32 %x) #1 {
entry:
  %a = add i32 %x, 1
  %b = mul i32 %a, 3
  ret i32 %b
}

attributes #0 = { "no_obfuscate" }
attributes #1 = { "obf_skip" }

