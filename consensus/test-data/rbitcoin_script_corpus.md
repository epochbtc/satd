<!--
Copied unchanged, with rbitcoin_script_corpus.json, from rbitcoin
(https://github.com/reardencode/rbitcoin) at bb06e8d3,
crates/rbitcoin-consensus/tests/fixtures/script_corpus/. Run by
consensus/tests/rbitcoin_corpus.rs. rbitcoin is licensed MIT OR Apache-2.0;
these files are used under the MIT license:

MIT License

Copyright (c) 2026 rbitcoin contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
-->

# Script corpus

Run beside Bitcoin Core's JSON suites. Every row is executed by our
interpreter and by Bitcoin Core v31.1 `VerifyScript` (the submodule, not
the crates.io `bitcoinconsensus` crate, which is Core 26). Both must
agree with the row's expected accept or reject. Error strings are not
compared.

This is not a proof over every byte string. secp256k1 is a shared
library. Block sigop cost, the milestone script skip, and transaction
structure are outside this corpus. Policy flags that confirm never sets
appear only as rows that leave them off.

The `row` array is Core `script_tests.json` form
`[scriptSig, scriptPubKey, flags, result]`, or the witness form
`[witness, scriptSig, scriptPubKey, flags, result]`. Either can be
appended upstream without a runner change.

Witness v0 and tapscript rows are spends, so both engines see them
through `VerifyScript`. Legacy rows are bare scripts with no flags.

## Vectors

| Id | Predicate |
|----|-----------|
| `smoke-op-1` | Harness: empty scriptSig, `OP_1` scriptPubKey, no flags, accepts on both engines. |
| `script-len-10000-legacy` | Legacy and witness v0 accept a 10,000-byte script. Tapscript has no script-size cap. |
| `script-len-10000-v0` | Legacy and witness v0 accept a 10,000-byte script. Tapscript has no script-size cap. |
| `script-len-10000-tapscript` | Legacy and witness v0 accept a 10,000-byte script. Tapscript has no script-size cap. |
| `script-len-10001-legacy` | Legacy and witness v0 reject a 10,001-byte script. Tapscript accepts it. |
| `script-len-10001-v0` | Legacy and witness v0 reject a 10,001-byte script. Tapscript accepts it. |
| `script-len-10001-tapscript` | Legacy and witness v0 reject a 10,001-byte script. Tapscript accepts it. |
| `push-520-legacy` | A 520-byte push is the element maximum and accepts. |
| `push-520-v0` | A 520-byte push is the element maximum and accepts. |
| `push-520-tapscript` | A 520-byte push is the element maximum and accepts. |
| `push-521-legacy` | A 521-byte push rejects. |
| `push-521-v0` | A 521-byte push rejects. |
| `push-521-tapscript` | A 521-byte push rejects. |
| `push-520-unexec-legacy` | A 520-byte push inside an unexecuted IF accepts. The element cap still applies there. |
| `push-520-unexec-v0` | A 520-byte push inside an unexecuted IF accepts. The element cap still applies there. |
| `push-520-unexec-tapscript` | A 520-byte push inside an unexecuted IF accepts. The element cap still applies there. |
| `push-521-unexec-legacy` | A 521-byte push inside an unexecuted IF rejects. |
| `push-521-unexec-v0` | A 521-byte push inside an unexecuted IF rejects. |
| `push-521-unexec-tapscript` | A 521-byte push inside an unexecuted IF rejects. |
| `ops-201-legacy` | 201 non-push opcodes accept on legacy and witness v0. Tapscript has no opcode cap. |
| `ops-201-v0` | 201 non-push opcodes accept on legacy and witness v0. Tapscript has no opcode cap. |
| `ops-201-tapscript` | 201 non-push opcodes accept on legacy and witness v0. Tapscript has no opcode cap. |
| `ops-202-legacy` | 202 non-push opcodes reject on legacy and witness v0. Tapscript accepts them. |
| `ops-202-v0` | 202 non-push opcodes reject on legacy and witness v0. Tapscript accepts them. |
| `ops-202-tapscript` | 202 non-push opcodes reject on legacy and witness v0. Tapscript accepts them. |
| `ops-unexec-201-legacy` | Opcodes inside an unexecuted IF count. IF plus 199 NOP plus ENDIF is 201 and accepts. |
| `ops-unexec-201-v0` | Opcodes inside an unexecuted IF count. IF plus 199 NOP plus ENDIF is 201 and accepts. |
| `ops-unexec-201-tapscript` | Opcodes inside an unexecuted IF count. IF plus 199 NOP plus ENDIF is 201 and accepts. |
| `ops-unexec-202-legacy` | IF plus 200 NOP plus ENDIF is 202. Legacy and witness v0 reject. Tapscript accepts. |
| `ops-unexec-202-v0` | IF plus 200 NOP plus ENDIF is 202. Legacy and witness v0 reject. Tapscript accepts. |
| `ops-unexec-202-tapscript` | IF plus 200 NOP plus ENDIF is 202. Legacy and witness v0 reject. Tapscript accepts. |
| `op16-excluded-legacy` | OP_0 through OP_16 do not count toward the 201 opcode cap. 202 OP_16 plus 201 DROP accepts. |
| `op16-excluded-v0` | OP_0 through OP_16 do not count toward the 201 opcode cap. 202 OP_16 plus 201 DROP accepts. |
| `op16-excluded-tapscript` | OP_0 through OP_16 do not count toward the 201 opcode cap. 202 OP_16 plus 201 DROP accepts. |
| `trunc-pushdata1-legacy` | A truncated PUSHDATA rejects in every signature version. |
| `trunc-pushdata1-v0` | A truncated PUSHDATA rejects in every signature version. |
| `trunc-pushdata1-tapscript` | A truncated PUSHDATA rejects in every signature version. |
| `trunc-pushdata2-legacy` | A truncated PUSHDATA rejects in every signature version. |
| `trunc-pushdata2-v0` | A truncated PUSHDATA rejects in every signature version. |
| `trunc-pushdata2-tapscript` | A truncated PUSHDATA rejects in every signature version. |
| `trunc-pushdata4-legacy` | A truncated PUSHDATA rejects in every signature version. |
| `trunc-pushdata4-v0` | A truncated PUSHDATA rejects in every signature version. |
| `trunc-pushdata4-tapscript` | A truncated PUSHDATA rejects in every signature version. |
| `else-empty-legacy` | ELSE with an empty condition stack rejects. |
| `else-empty-v0` | ELSE with an empty condition stack rejects. |
| `else-empty-tapscript` | ELSE with an empty condition stack rejects. |
| `endif-empty-legacy` | ENDIF with an empty condition stack rejects. |
| `endif-empty-v0` | ENDIF with an empty condition stack rejects. |
| `endif-empty-tapscript` | ENDIF with an empty condition stack rejects. |
| `if-unclosed-legacy` | An unclosed IF rejects. |
| `if-unclosed-v0` | An unclosed IF rejects. |
| `if-unclosed-tapscript` | An unclosed IF rejects. |
| `verif-unexec-legacy` | OP_VERIF rejects even inside an unexecuted IF, in every signature version. |
| `verif-unexec-v0` | OP_VERIF rejects even inside an unexecuted IF, in every signature version. |
| `verif-unexec-tapscript` | OP_VERIF rejects even inside an unexecuted IF, in every signature version. |
| `vernotif-unexec-legacy` | OP_VERNOTIF rejects even inside an unexecuted IF, in every signature version. |
| `vernotif-unexec-v0` | OP_VERNOTIF rejects even inside an unexecuted IF, in every signature version. |
| `vernotif-unexec-tapscript` | OP_VERNOTIF rejects even inside an unexecuted IF, in every signature version. |
| `verif-exec-legacy` | OP_VERIF in the taken IF branch rejects, in every signature version. |
| `verif-exec-v0` | OP_VERIF in the taken IF branch rejects, in every signature version. |
| `verif-exec-tapscript` | OP_VERIF in the taken IF branch rejects, in every signature version. |
| `vernotif-exec-legacy` | OP_VERNOTIF in the taken IF branch rejects, in every signature version. |
| `vernotif-exec-v0` | OP_VERNOTIF in the taken IF branch rejects, in every signature version. |
| `vernotif-exec-tapscript` | OP_VERNOTIF in the taken IF branch rejects, in every signature version. |
| `stack-1000-legacy` | Legacy main stack of 1,000 accepts. Cleanstack is off. |
| `stack-1001-legacy` | Legacy main stack of 1,001 rejects. |
| `stack-alt-1000-legacy` | Legacy main stack plus altstack of 1,000 accepts: 201 items moved aside, then 799 more. |
| `stack-alt-1001-legacy` | One more push after that shared 1,000 rejects. The opcode budget is already exactly 201. |
| `stack-1001-v0` | Witness v0 rejects a 1,001st stack push. A successful 1,000-deep witness script cannot also return to one element within the 201 opcode budget, so the accept side is the legacy and tapscript rows. |
| `stack-exec-1000-tapscript` | Tapscript enforces the shared 1,000 cap after each opcode. 1,000 pushes and 999 drops leave one true item. |
| `stack-exec-1001-tapscript` | Tapscript rejects the 1,001st push during execution. |
| `tuck-1000-legacy` | OP_TUCK counts toward the shared 1,000 cap. 999 pushes and TUCK make 1,000 and accept. |
| `tuck-1001-legacy` | OP_TUCK on a stack of 1,000 makes 1,001 and rejects. |
| `tuck-1000-tapscript` | Tapscript OP_TUCK to 1,000, then 999 drops leave one true item. |
| `tuck-1001-tapscript` | Tapscript OP_TUCK to 1,001 rejects, even though later drops would leave one true item. |
| `initial-1001-ripemd160-v0` | Witness v0 has no initial stack check. RIPEMD160 on 1,001 items leaves 1,001 and rejects. |
| `initial-1001-hash256-v0` | Witness v0 has no initial stack check. HASH256 on 1,001 items leaves 1,001 and rejects. |
| `disabled-cat-unexec-legacy` | OP_CAT (0x7e) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-cat-unexec-v0` | OP_CAT (0x7e) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-cat-unexec-tapscript` | OP_CAT (0x7e) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-substr-unexec-legacy` | OP_SUBSTR (0x7f) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-substr-unexec-v0` | OP_SUBSTR (0x7f) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-substr-unexec-tapscript` | OP_SUBSTR (0x7f) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-left-unexec-legacy` | OP_LEFT (0x80) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-left-unexec-v0` | OP_LEFT (0x80) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-left-unexec-tapscript` | OP_LEFT (0x80) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-right-unexec-legacy` | OP_RIGHT (0x81) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-right-unexec-v0` | OP_RIGHT (0x81) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-right-unexec-tapscript` | OP_RIGHT (0x81) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-invert-unexec-legacy` | OP_INVERT (0x83) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-invert-unexec-v0` | OP_INVERT (0x83) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-invert-unexec-tapscript` | OP_INVERT (0x83) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-and-unexec-legacy` | OP_AND (0x84) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-and-unexec-v0` | OP_AND (0x84) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-and-unexec-tapscript` | OP_AND (0x84) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-or-unexec-legacy` | OP_OR (0x85) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-or-unexec-v0` | OP_OR (0x85) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-or-unexec-tapscript` | OP_OR (0x85) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-xor-unexec-legacy` | OP_XOR (0x86) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-xor-unexec-v0` | OP_XOR (0x86) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-xor-unexec-tapscript` | OP_XOR (0x86) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-2mul-unexec-legacy` | OP_2MUL (0x8d) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-2mul-unexec-v0` | OP_2MUL (0x8d) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-2mul-unexec-tapscript` | OP_2MUL (0x8d) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-2div-unexec-legacy` | OP_2DIV (0x8e) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-2div-unexec-v0` | OP_2DIV (0x8e) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-2div-unexec-tapscript` | OP_2DIV (0x8e) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-mul-unexec-legacy` | OP_MUL (0x95) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-mul-unexec-v0` | OP_MUL (0x95) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-mul-unexec-tapscript` | OP_MUL (0x95) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-div-unexec-legacy` | OP_DIV (0x96) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-div-unexec-v0` | OP_DIV (0x96) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-div-unexec-tapscript` | OP_DIV (0x96) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-mod-unexec-legacy` | OP_MOD (0x97) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-mod-unexec-v0` | OP_MOD (0x97) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-mod-unexec-tapscript` | OP_MOD (0x97) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-lshift-unexec-legacy` | OP_LSHIFT (0x98) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-lshift-unexec-v0` | OP_LSHIFT (0x98) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-lshift-unexec-tapscript` | OP_LSHIFT (0x98) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-rshift-unexec-legacy` | OP_RSHIFT (0x99) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-rshift-unexec-v0` | OP_RSHIFT (0x99) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `disabled-rshift-unexec-tapscript` | OP_RSHIFT (0x99) rejects in legacy and witness v0 even inside an unexecuted IF. In tapscript that byte is OP_SUCCESS and accepts. |
| `exec-reserved-legacy` | 0x50 (RESERVED) rejects when executed on legacy and witness v0. Tapscript accepts it as OP_SUCCESS. |
| `exec-reserved-v0` | 0x50 (RESERVED) rejects when executed on legacy and witness v0. Tapscript accepts it as OP_SUCCESS. |
| `exec-reserved-tapscript` | 0x50 (RESERVED) rejects when executed on legacy and witness v0. Tapscript accepts it as OP_SUCCESS. |
| `unexec-reserved-legacy` | 0x50 (RESERVED) is not a legacy disabled opcode, so an unexecuted one is skipped. Tapscript still accepts it as OP_SUCCESS. |
| `unexec-reserved-v0` | 0x50 (RESERVED) is not a legacy disabled opcode, so an unexecuted one is skipped. Tapscript still accepts it as OP_SUCCESS. |
| `unexec-reserved-tapscript` | 0x50 (RESERVED) is not a legacy disabled opcode, so an unexecuted one is skipped. Tapscript still accepts it as OP_SUCCESS. |
| `exec-ver-legacy` | 0x62 (VER) rejects when executed on legacy and witness v0. Tapscript accepts it as OP_SUCCESS. |
| `exec-ver-v0` | 0x62 (VER) rejects when executed on legacy and witness v0. Tapscript accepts it as OP_SUCCESS. |
| `exec-ver-tapscript` | 0x62 (VER) rejects when executed on legacy and witness v0. Tapscript accepts it as OP_SUCCESS. |
| `unexec-ver-legacy` | 0x62 (VER) is not a legacy disabled opcode, so an unexecuted one is skipped. Tapscript still accepts it as OP_SUCCESS. |
| `unexec-ver-v0` | 0x62 (VER) is not a legacy disabled opcode, so an unexecuted one is skipped. Tapscript still accepts it as OP_SUCCESS. |
| `unexec-ver-tapscript` | 0x62 (VER) is not a legacy disabled opcode, so an unexecuted one is skipped. Tapscript still accepts it as OP_SUCCESS. |
| `exec-reserved1-legacy` | 0x89 (RESERVED1) rejects when executed on legacy and witness v0. Tapscript accepts it as OP_SUCCESS. |
| `exec-reserved1-v0` | 0x89 (RESERVED1) rejects when executed on legacy and witness v0. Tapscript accepts it as OP_SUCCESS. |
| `exec-reserved1-tapscript` | 0x89 (RESERVED1) rejects when executed on legacy and witness v0. Tapscript accepts it as OP_SUCCESS. |
| `unexec-reserved1-legacy` | 0x89 (RESERVED1) is not a legacy disabled opcode, so an unexecuted one is skipped. Tapscript still accepts it as OP_SUCCESS. |
| `unexec-reserved1-v0` | 0x89 (RESERVED1) is not a legacy disabled opcode, so an unexecuted one is skipped. Tapscript still accepts it as OP_SUCCESS. |
| `unexec-reserved1-tapscript` | 0x89 (RESERVED1) is not a legacy disabled opcode, so an unexecuted one is skipped. Tapscript still accepts it as OP_SUCCESS. |
| `exec-reserved2-legacy` | 0x8a (RESERVED2) rejects when executed on legacy and witness v0. Tapscript accepts it as OP_SUCCESS. |
| `exec-reserved2-v0` | 0x8a (RESERVED2) rejects when executed on legacy and witness v0. Tapscript accepts it as OP_SUCCESS. |
| `exec-reserved2-tapscript` | 0x8a (RESERVED2) rejects when executed on legacy and witness v0. Tapscript accepts it as OP_SUCCESS. |
| `unexec-reserved2-legacy` | 0x8a (RESERVED2) is not a legacy disabled opcode, so an unexecuted one is skipped. Tapscript still accepts it as OP_SUCCESS. |
| `unexec-reserved2-v0` | 0x8a (RESERVED2) is not a legacy disabled opcode, so an unexecuted one is skipped. Tapscript still accepts it as OP_SUCCESS. |
| `unexec-reserved2-tapscript` | 0x8a (RESERVED2) is not a legacy disabled opcode, so an unexecuted one is skipped. Tapscript still accepts it as OP_SUCCESS. |
| `exec-success187-legacy` | 0xbb (SUCCESS187) rejects when executed on legacy and witness v0. Tapscript accepts it as OP_SUCCESS. |
| `exec-success187-v0` | 0xbb (SUCCESS187) rejects when executed on legacy and witness v0. Tapscript accepts it as OP_SUCCESS. |
| `exec-success187-tapscript` | 0xbb (SUCCESS187) rejects when executed on legacy and witness v0. Tapscript accepts it as OP_SUCCESS. |
| `unexec-success187-legacy` | 0xbb (SUCCESS187) is not a legacy disabled opcode, so an unexecuted one is skipped. Tapscript still accepts it as OP_SUCCESS. |
| `unexec-success187-v0` | 0xbb (SUCCESS187) is not a legacy disabled opcode, so an unexecuted one is skipped. Tapscript still accepts it as OP_SUCCESS. |
| `unexec-success187-tapscript` | 0xbb (SUCCESS187) is not a legacy disabled opcode, so an unexecuted one is skipped. Tapscript still accepts it as OP_SUCCESS. |
| `exec-success254-legacy` | 0xfe (SUCCESS254) rejects when executed on legacy and witness v0. Tapscript accepts it as OP_SUCCESS. |
| `exec-success254-v0` | 0xfe (SUCCESS254) rejects when executed on legacy and witness v0. Tapscript accepts it as OP_SUCCESS. |
| `exec-success254-tapscript` | 0xfe (SUCCESS254) rejects when executed on legacy and witness v0. Tapscript accepts it as OP_SUCCESS. |
| `unexec-success254-legacy` | 0xfe (SUCCESS254) is not a legacy disabled opcode, so an unexecuted one is skipped. Tapscript still accepts it as OP_SUCCESS. |
| `unexec-success254-v0` | 0xfe (SUCCESS254) is not a legacy disabled opcode, so an unexecuted one is skipped. Tapscript still accepts it as OP_SUCCESS. |
| `unexec-success254-tapscript` | 0xfe (SUCCESS254) is not a legacy disabled opcode, so an unexecuted one is skipped. Tapscript still accepts it as OP_SUCCESS. |
| `exec-return-legacy` | OP_RETURN rejects when executed in every signature version. |
| `exec-return-v0` | OP_RETURN rejects when executed in every signature version. |
| `exec-return-tapscript` | OP_RETURN rejects when executed in every signature version. |
| `unexec-return-legacy` | OP_RETURN inside an unexecuted IF is skipped in every signature version. |
| `unexec-return-v0` | OP_RETURN inside an unexecuted IF is skipped in every signature version. |
| `unexec-return-tapscript` | OP_RETURN inside an unexecuted IF is skipped in every signature version. |
| `exec-unknown-ff-legacy` | Opcode 0xff is not disabled and not OP_SUCCESS. Executing it rejects in every signature version. |
| `exec-unknown-ff-v0` | Opcode 0xff is not disabled and not OP_SUCCESS. Executing it rejects in every signature version. |
| `exec-unknown-ff-tapscript` | Opcode 0xff is not disabled and not OP_SUCCESS. Executing it rejects in every signature version. |
| `unexec-unknown-ff-legacy` | Opcode 0xff inside an unexecuted IF is skipped in every signature version. |
| `unexec-unknown-ff-v0` | Opcode 0xff inside an unexecuted IF is skipped in every signature version. |
| `unexec-unknown-ff-tapscript` | Opcode 0xff inside an unexecuted IF is skipped in every signature version. |
| `success-inside-push-tapscript` | An OP_SUCCESS byte inside a push is data. The following OP_RETURN still rejects. |
| `initial-1000-tapscript` | Tapscript accepts an initial stack of 1,000, then 999 DROP leaves one true item. |
| `initial-1001-tapscript` | Tapscript rejects an initial stack of 1,001 before the script runs. |
| `initial-520-tapscript` | Tapscript accepts a 520-byte initial element. |
| `initial-521-tapscript` | Tapscript rejects a 521-byte initial element. |
| `initial-520-v0` | Witness v0 accepts a 520-byte initial element. |
| `initial-521-v0` | Witness v0 rejects a 521-byte initial element. |
| `success-skip-1001` | One OP_SUCCESS accepts before the initial-stack check, including 1,001 items. |
| `success-unexec-1001` | OP_SUCCESS inside an unexecuted IF still accepts before the initial-stack check. |
| `success-unparseable-tail` | OP_SUCCESS followed by a truncated PUSHDATA accepts before the stack check. The unparseable tail is not executed. |
| `success187-skip-1001` | OP_SUCCESS187 accepts before the 1,001 initial-stack check. |
| `success-skip-521` | OP_SUCCESS accepts before the 521-byte initial-element check. |
| `num-max-roundtrip-legacy` | The 4-byte maximum positive script number decodes, survives ADD 0, and compares equal. Minimal-encoding checks stay off. |
| `num-max-roundtrip-v0` | The 4-byte maximum positive script number decodes, survives ADD 0, and compares equal. Minimal-encoding checks stay off. |
| `num-max-roundtrip-tapscript` | The 4-byte maximum positive script number decodes, survives ADD 0, and compares equal. Minimal-encoding checks stay off. |
| `num-5byte-arith-legacy` | Arithmetic rejects a 5-byte number. CLTV and CSV are the opcodes that allow 5. |
| `num-5byte-arith-v0` | Arithmetic rejects a 5-byte number. CLTV and CSV are the opcodes that allow 5. |
| `num-5byte-arith-tapscript` | Arithmetic rejects a 5-byte number. CLTV and CSV are the opcodes that allow 5. |
| `add-result-may-be-wide-legacy` | ADD of 2147483647 and 1 accepts. The sum does not fit in 4 bytes and stays on the stack for later. |
| `add-result-may-be-wide-v0` | ADD of 2147483647 and 1 accepts. The sum does not fit in 4 bytes and stays on the stack for later. |
| `add-result-may-be-wide-tapscript` | ADD of 2147483647 and 1 accepts. The sum does not fit in 4 bytes and stays on the stack for later. |
| `add-wide-result-not-reused-legacy` | That wide sum rejects when a later arithmetic opcode decodes it. |
| `add-wide-result-not-reused-v0` | That wide sum rejects when a later arithmetic opcode decodes it. |
| `add-wide-result-not-reused-tapscript` | That wide sum rejects when a later arithmetic opcode decodes it. |
| `add-two-max-legacy` | ADD of two 4-byte maximums accepts. The sum is wider than 4 bytes and is not itself an error. |
| `add-two-max-v0` | ADD of two 4-byte maximums accepts. The sum is wider than 4 bytes and is not itself an error. |
| `add-two-max-tapscript` | ADD of two 4-byte maximums accepts. The sum is wider than 4 bytes and is not itself an error. |
| `sub-underflow-wide-legacy` | SUB of 0 minus the 4-byte maximum accepts and leaves a negative wide result. |
| `sub-underflow-wide-v0` | SUB of 0 minus the 4-byte maximum accepts and leaves a negative wide result. |
| `sub-underflow-wide-tapscript` | SUB of 0 minus the 4-byte maximum accepts and leaves a negative wide result. |
| `negate-negzero-legacy` | Four-byte 0x00000080 is negative zero when minimal checks are off. Negating it is 0. |
| `negate-negzero-v0` | Four-byte 0x00000080 is negative zero when minimal checks are off. Negating it is 0. |
| `negate-negzero-tapscript` | Four-byte 0x00000080 is negative zero when minimal checks are off. Negating it is 0. |
| `negate-i32-min-5byte-legacy` | The 5-byte encoding of negative 2^31 is not a 4-byte script number. NEGATE rejects it. |
| `negate-i32-min-5byte-v0` | The 5-byte encoding of negative 2^31 is not a 4-byte script number. NEGATE rejects it. |
| `negate-i32-min-5byte-tapscript` | The 5-byte encoding of negative 2^31 is not a 4-byte script number. NEGATE rejects it. |
| `zero-negzero-numequal-legacy` | 0 and negative zero (0x80) are equal as numbers when minimal encoding is not required. |
| `zero-negzero-numequal-v0` | 0 and negative zero (0x80) are equal as numbers when minimal encoding is not required. |
| `zero-negzero-numequal-tapscript` | 0 and negative zero (0x80) are equal as numbers when minimal encoding is not required. |
| `zero-negzero-equal-legacy` | The same two values are not equal as byte strings under OP_EQUAL. |
| `zero-negzero-equal-v0` | The same two values are not equal as byte strings under OP_EQUAL. |
| `zero-negzero-equal-tapscript` | The same two values are not equal as byte strings under OP_EQUAL. |
| `within-inside-legacy` | WITHIN is inclusive of the low bound. |
| `within-inside-v0` | WITHIN is inclusive of the low bound. |
| `within-inside-tapscript` | WITHIN is inclusive of the low bound. |
| `within-low-legacy` | WITHIN accepts the low bound itself. |
| `within-low-v0` | WITHIN accepts the low bound itself. |
| `within-low-tapscript` | WITHIN accepts the low bound itself. |
| `within-high-legacy` | WITHIN rejects the high bound. |
| `within-high-v0` | WITHIN rejects the high bound. |
| `within-high-tapscript` | WITHIN rejects the high bound. |
| `pick-zero-legacy` | PICK index 0 copies the top item. DROP leaves that one true item. |
| `pick-zero-v0` | PICK index 0 copies the top item. DROP leaves that one true item. |
| `pick-zero-tapscript` | PICK index 0 copies the top item. DROP leaves that one true item. |
| `pick-negative-legacy` | PICK index -1 rejects. |
| `pick-negative-v0` | PICK index -1 rejects. |
| `pick-negative-tapscript` | PICK index -1 rejects. |
| `pick-depth-legacy` | PICK index equal to the remaining stack depth rejects. |
| `pick-depth-v0` | PICK index equal to the remaining stack depth rejects. |
| `pick-depth-tapscript` | PICK index equal to the remaining stack depth rejects. |
| `roll-zero-legacy` | ROLL index 0 leaves the same one item. |
| `roll-zero-v0` | ROLL index 0 leaves the same one item. |
| `roll-zero-tapscript` | ROLL index 0 leaves the same one item. |
| `roll-negative-legacy` | ROLL index -1 rejects. |
| `roll-negative-v0` | ROLL index -1 rejects. |
| `roll-negative-tapscript` | ROLL index -1 rejects. |
| `roll-depth-legacy` | ROLL index equal to the remaining stack depth rejects. |
| `roll-depth-v0` | ROLL index equal to the remaining stack depth rejects. |
| `roll-depth-tapscript` | ROLL index equal to the remaining stack depth rejects. |
| `if-minimal-true-legacy` | IF of a single 0x01 takes the branch. |
| `if-minimal-true-v0` | IF of a single 0x01 takes the branch. |
| `if-minimal-true-tapscript` | IF of a single 0x01 takes the branch. |
| `if-minimal-empty-legacy` | IF of an empty vector is false and is a minimal argument in every signature version. |
| `if-minimal-empty-v0` | IF of an empty vector is false and is a minimal argument in every signature version. |
| `if-minimal-empty-tapscript` | IF of an empty vector is false and is a minimal argument in every signature version. |
| `minimalif-00-legacy` | A bare script ignores MINIMALIF. A single 0x00 is false, the branch is skipped, and the trailing OP_1 accepts. |
| `minimalif-00-v0-off` | Witness v0 accepts a non-minimal IF argument when MINIMALIF is off. |
| `minimalif-00-v0-on` | Witness v0 rejects a single 0x00 IF argument when MINIMALIF is on. |
| `minimalif-00-tapscript` | Tapscript rejects a single 0x00 IF argument even when the MINIMALIF flag is off. |
| `minimalif-negzero-tapscript` | Tapscript rejects negative zero as an IF argument. |
| `minimalif-negzero-v0-off` | Witness v0 accepts negative zero as a false IF argument when MINIMALIF is off. |
| `minimalif-02-legacy` | A bare script with MINIMALIF still accepts OP_2 as an IF argument. |
| `minimalif-02-tapscript` | Tapscript rejects OP_2 as an IF argument. The only minimal true byte is 0x01. |
| `bool-leading-zero-legacy` | cast_to_bool is true when any byte is non-zero, including a leading zero. |
| `bool-leading-zero-v0` | cast_to_bool is true when any byte is non-zero, including a leading zero. |
| `bool-leading-zero-tapscript` | Tapscript MINIMALIF rejects that two-byte true value before cast_to_bool. The only minimal true argument is a single 0x01. |
| `bool-negzero-legacy` | Negative zero is false, so IF takes the ELSE branch. |
| `bool-negzero-v0` | Witness v0 treats negative zero as false when MINIMALIF is off. |
| `unexec-does-not-push-legacy` | An unexecuted IF branch does not push. ELSE leaves the single true item. |
| `unexec-does-not-push-v0` | An unexecuted IF branch does not push. ELSE leaves the single true item. |
| `unexec-does-not-push-tapscript` | An unexecuted IF branch does not push. ELSE leaves the single true item. |
| `minimaldata-unexec-legacy` | MINIMALDATA does not apply inside an unexecuted IF. |
| `minimaldata-exec-legacy` | MINIMALDATA rejects an executed push of 0x01 that is not OP_1. |
| `minimaldata-unexec-v0` | Witness v0 MINIMALDATA does not apply inside an unexecuted IF. |
| `minimaldata-exec-v0` | Witness v0 MINIMALDATA rejects an executed non-minimal push. |
| `unexec-checksigverify-legacy` | CHECKSIGVERIFY in an unexecuted branch does not run. |
| `unexec-checksigverify-v0` | CHECKSIGVERIFY in an unexecuted branch does not run. |
| `unexec-checksigverify-tapscript` | CHECKSIGVERIFY in an unexecuted branch does not run. |
| `exec-checksigverify-empty-legacy` | CHECKSIGVERIFY of an empty signature rejects when the branch runs. |
| `exec-checksigverify-empty-v0` | CHECKSIGVERIFY of an empty signature rejects when the branch runs. |
| `exec-checksigverify-empty-tapscript` | CHECKSIGVERIFY of an empty signature rejects when the branch runs. |

Core `script_tests.json` already has both an accept and a reject for NOP, VERIFY, TOALTSTACK, FROMALTSTACK, 2DROP, 2DUP, 3DUP, 2OVER, 2ROT, 2SWAP, IFDUP, DEPTH, DROP, DUP, NIP, OVER, PICK, ROLL, ROT, SWAP, TUCK, and SIZE. Those success arms are not duplicated here. The rows below are the boundary pairs this corpus names itself.

| Id | Predicate |
|----|-----------|
| `stack-underflow-drop` | One empty-stack underflow through the shared pop: DROP with nothing on the stack rejects. |
| `stack-2rot-6` | 2ROT with 6 items accepts. The top item is the original second value and is true. |
| `stack-2rot-5` | 2ROT with 5 items rejects. |
| `stack-fromalt-ok` | TOALTSTACK then FROMALTSTACK returns the same true item. |
| `stack-fromalt-empty` | FROMALTSTACK on an empty altstack rejects. |

## Checksig, multisig, find-and-delete, and sighash

An optional `spend` object sets `version`, `locktime`, `sequence`, and `n_outputs` on the spending transaction only. A missing object is version 1, locktime 0, sequence `0xffffffff`, and one output. `version` is the consensus i32 bit pattern.

Unknown hashtype bytes are a STRICTENC check. DERSIG checks the DER encoding and still accepts hashtype `0x00`, `0x04`, `0x80`, and `0x85`. The signature is over that raw byte, so rewriting it to a standard type rejects. LOW_S stays off.

FindAndDelete is observed with an empty signature. Its needle is the single byte `OP_0`. A verifying signature is not placed in `scriptPubKey`, because this credit template would make that signature commit to a txid that already contains it. A `0x00` buried in a push is the off-boundary case. A signature longer than `scriptCode` is the no-op already covered by `sighash-all-legacy`.

CHECKSIGVERIFY of an empty signature is `exec-checksigverify-empty-legacy`, `exec-checksigverify-empty-v0`, and `exec-checksigverify-empty-tapscript`. The new rows are the CHECKSIG continue side.

Tapscript validation weight: one non-empty CHECKSIGADD against a 1-byte pubkey accepts, two exceed the budget, and the same count of empty signatures still accepts.

| Id | Predicate |
|----|-----------|
| `hash-sha1-empty` | OP_sha1 of empty matches the known digest. |
| `hash-sha1-abc` | OP_sha1 of abc matches the known digest. |
| `hash-sha256-empty` | OP_sha256 of empty matches the known digest. |
| `hash-sha256-abc` | OP_sha256 of abc matches the known digest. |
| `hash-ripemd160-empty` | OP_ripemd160 of empty matches the known digest. |
| `hash-ripemd160-abc` | OP_ripemd160 of abc matches the known digest. |
| `hash-hash160-empty` | OP_hash160 of empty matches the known digest. |
| `hash-hash160-abc` | OP_hash160 of abc matches the known digest. |
| `hash-hash256-empty` | OP_hash256 of empty matches the known digest. |
| `hash-hash256-abc` | OP_hash256 of abc matches the known digest. |
| `hash-sha256-abc-mismatch` | SHA256 of abc compared to 32 zero bytes rejects. |
| `sighash-all-legacy` | Legacy CHECKSIG accepts SIGHASH all with LOW_S off. |
| `sighash-all-v0` | Witness v0 CHECKSIG accepts SIGHASH all. |
| `sighash-none-legacy` | Legacy CHECKSIG accepts SIGHASH none with LOW_S off. |
| `sighash-none-v0` | Witness v0 CHECKSIG accepts SIGHASH none. |
| `sighash-single-legacy` | Legacy CHECKSIG accepts SIGHASH single with LOW_S off. An in-range SINGLE digest is not uint256 one. |
| `sighash-single-v0` | Witness v0 CHECKSIG accepts SIGHASH single. |
| `sighash-all-acp-legacy` | Legacy CHECKSIG accepts SIGHASH all-acp with LOW_S off. |
| `sighash-all-acp-v0` | Witness v0 CHECKSIG accepts SIGHASH all-acp. |
| `sighash-none-acp-legacy` | Legacy CHECKSIG accepts SIGHASH none-acp with LOW_S off. |
| `sighash-none-acp-v0` | Witness v0 CHECKSIG accepts SIGHASH none-acp. |
| `sighash-single-acp-legacy` | Legacy CHECKSIG accepts SIGHASH single-acp with LOW_S off. An in-range SINGLE digest is not uint256 one. |
| `sighash-single-acp-v0` | Witness v0 CHECKSIG accepts SIGHASH single-acp. |
| `sighash-wrongtype-legacy` | A legacy signature signed as ALL and rewritten as NONE rejects. |
| `sighash-wrongtype-v0` | A witness v0 signature signed as ALL and rewritten as NONE rejects. |
| `sighash-single-past-legacy` | Legacy SIGHASH_SINGLE with no output hashes uint256 one and the signature of that digest accepts. |
| `sighash-single-past-v0` | Witness v0 SIGHASH_SINGLE with no output hashes the BIP143 empty-output digest, not uint256 one. |
| `sighash-type04-dersig-legacy` | DERSIG alone accepts a defined-DER signature whose hashtype byte is 0x04. |
| `sighash-type04-strictenc-legacy` | STRICTENC rejects hashtype 0x04. LOW_S stays off. |
| `sighash-type04-dersig-v0` | Witness v0 DERSIG alone accepts hashtype 0x04. |
| `sighash-type04-strictenc-v0` | Witness v0 STRICTENC rejects hashtype 0x04. |
| `sighash-type00-dersig-legacy` | DERSIG accepts hashtype 0x00. The digest uses that raw byte, not SIGHASH_ALL. |
| `sighash-type00-strictenc-legacy` | STRICTENC rejects hashtype 0x00. |
| `sighash-type00-as-01-legacy` | The 0x00 signature with its type byte rewritten to 0x01 rejects. |
| `sighash-type00-dersig-v0` | Witness v0 DERSIG accepts hashtype 0x00. |
| `sighash-type00-strictenc-v0` | Witness v0 STRICTENC rejects hashtype 0x00. |
| `sighash-type00-as-01-v0` | Witness v0 rejects the 0x00 signature rewritten to 0x01. |
| `sighash-type80-dersig-legacy` | DERSIG accepts hashtype 0x80 (ANYONECANPAY with base 0). |
| `sighash-type80-strictenc-legacy` | STRICTENC rejects hashtype 0x80. |
| `sighash-type80-as-81-legacy` | The 0x80 signature rewritten to 0x81 rejects. |
| `sighash-type80-dersig-v0` | Witness v0 DERSIG accepts hashtype 0x80. |
| `sighash-type80-strictenc-v0` | Witness v0 STRICTENC rejects hashtype 0x80. |
| `sighash-type80-as-81-v0` | Witness v0 rejects the 0x80 signature rewritten to 0x81. |
| `sighash-type85-dersig-legacy` | DERSIG accepts hashtype 0x85 (ANYONECANPAY with base 5). |
| `sighash-type85-strictenc-legacy` | STRICTENC rejects hashtype 0x85. |
| `sighash-type85-as-81-legacy` | The 0x85 signature rewritten to 0x81 rejects. |
| `sighash-type85-dersig-v0` | Witness v0 DERSIG accepts hashtype 0x85. |
| `sighash-type85-strictenc-v0` | Witness v0 STRICTENC rejects hashtype 0x85. |
| `sighash-type85-as-81-v0` | Witness v0 rejects the 0x85 signature rewritten to 0x81. |
| `dersig-off-nondet-legacy` | With DERSIG and LOW_S off, a non-minimal S that the lax parser accepts still verifies. |
| `dersig-on-nondet-legacy` | DERSIG rejects that non-minimal S. LOW_S stays off. |
| `dersig-off-nondet-v0` | Witness v0 with DERSIG off accepts the same non-minimal S. |
| `dersig-on-nondet-v0` | Witness v0 DERSIG rejects the non-minimal S. |
| `checksig-empty-continues-legacy` | An empty legacy signature is false, not an encoding failure, so CHECKSIG NOT leaves true. |
| `checksig-empty-continues-v0` | An empty witness v0 signature is false, so CHECKSIG NOT leaves true. |
| `checksig-badenc-dersig-off-legacy` | With DERSIG off, a non-empty signature the lax parser rejects is false and CHECKSIG NOT leaves true. |
| `checksig-badenc-dersig-on-legacy` | DERSIG rejects a non-empty non-DER signature before CHECKSIG can push false. |
| `checksig-badenc-dersig-off-v0` | Witness v0 with DERSIG off treats a non-DER signature as false. |
| `checksig-badenc-dersig-on-v0` | Witness v0 DERSIG rejects a non-DER signature. |
| `ecdsa-legacy-sig-on-v0` | The legacy ECDSA signature does not verify under the witness v0 sighash. |
| `ecdsa-v0-sig-on-legacy` | The witness v0 ECDSA signature does not verify under the legacy sighash. |
| `fad-empty-keeps-fail-legacy` | An empty signature deletes the aligned OP_0. A signature of the undeleted script then misses, the bad encoding is not tried, and NOT leaves true. |
| `fad-empty-deleted-match-legacy` | A signature of the script after that OP_0 is removed matches, so DERSIG rejects the bad encoding that the walk then tries. |
| `fad-v0-keeps-op0-match` | Witness v0 does not FindAndDelete, so the signature of the full script matches and the bad encoding is tried. |
| `fad-v0-keeps-op0-miss` | Witness v0 keeps the OP_0, so a signature of the shortened script misses and NOT leaves true. |
| `fad-offboundary-not-removed-legacy` | A 0x00 inside a push is not an empty-signature OP_0. The signature of the full script matches and the bad encoding is tried. |
| `fad-offboundary-as-if-deleted-legacy` | That buried 0x00 stays, so a signature of the shortened script misses and NOT leaves true. |
| `codesep-suffix-legacy` | Legacy OP_CODESEPARATOR drops the prefix from scriptCode. A signature of the suffix accepts. |
| `codesep-prefix-legacy` | A signature of the pre-separator script rejects once OP_CODESEPARATOR truncates scriptCode. |
| `codesep-suffix-v0` | Witness v0 OP_CODESEPARATOR drops the prefix from scriptCode. |
| `codesep-prefix-v0` | Witness v0 rejects a signature of the script from before OP_CODESEPARATOR. |
| `sighash-default-tap` | Tapscript CHECKSIG accepts sighash default. |
| `sighash-all-tap` | Tapscript CHECKSIG accepts sighash all. |
| `sighash-none-tap` | Tapscript CHECKSIG accepts sighash none. |
| `sighash-single-tap` | Tapscript CHECKSIG accepts sighash single. |
| `sighash-all-acp-tap` | Tapscript CHECKSIG accepts sighash all-acp. |
| `sighash-none-acp-tap` | Tapscript CHECKSIG accepts sighash none-acp. |
| `sighash-single-acp-tap` | Tapscript CHECKSIG accepts sighash single-acp. |
| `sighash-wrongtype-tap` | A tapscript signature signed as ALL and rewritten as NONE fails the check. |
| `sighash-type00-tap` | A 65-byte tapscript signature with hashtype 0x00 fails. |
| `sighash-type04-tap` | Tapscript rejects hashtype 0x04. |
| `sighash-single-past-tap` | Tapscript SIGHASH_SINGLE with no output at that input rejects instead of hashing uint256 one. |
| `checksig-empty-continues-tap` | An empty tapscript signature is false, so CHECKSIG NOT leaves true. |
| `checksig-invalid-tap` | A non-empty invalid tapscript signature is a hard failure. |
| `checksig-empty-pubkey-tap` | Tapscript CHECKSIG with an empty pubkey fails. |
| `checksig-unknown-pubkey-tap` | A tapscript pubkey that is not 32 bytes succeeds for a non-empty signature (upgrade hook). |
| `checksigadd-valid-tap` | CHECKSIGADD of a valid signature adds one. |
| `checksigadd-empty-tap` | CHECKSIGADD of an empty signature pushes n unchanged. |
| `checksigadd-invalid-tap` | CHECKSIGADD of a non-empty invalid signature fails. |
| `tap-weight-pass` | Tapscript validation weight still accepts one non-empty signature check. |
| `tap-weight-fail` | One more non-empty signature check (2) exceeds the tapscript weight budget. |
| `tap-weight-empty-free` | Empty tapscript signatures do not consume validation weight. |
| `codesep-pos0-tap` | Tapscript OP_CODESEPARATOR records instruction index 0, and a signature of that position accepts. |
| `codesep-ignored-tap` | A tapscript signature that omits the executed OP_CODESEPARATOR position fails. |
| `multisig-m0-n0-legacy` | CHECKMULTISIG with m = 0 and n = 0 accepts. |
| `multisig-m0-n0-v0` | Witness v0 CHECKMULTISIG with m = 0 and n = 0 accepts. |
| `multisig-n21-legacy` | CHECKMULTISIG rejects n = 21. |
| `multisig-n21-v0` | Witness v0 CHECKMULTISIG rejects n = 21. |
| `multisig-m-gt-n-legacy` | CHECKMULTISIG rejects m > n. |
| `multisig-m-negative-legacy` | CHECKMULTISIG rejects a negative m. |
| `multisig-m-negative-v0` | Witness v0 CHECKMULTISIG rejects a negative m. |
| `multisig-m20-n20-legacy` | CHECKMULTISIG with m = n = 20 accepts. The 20 keys stay inside the opcode budget. |
| `multisig-m20-n20-v0` | Witness v0 CHECKMULTISIG with m = n = 20 accepts. |
| `multisig-unused-badenc-legacy` | A bad encoding on a signature CHECKMULTISIG never tries is ignored, and NOT turns the failed match into true. |
| `multisig-tried-badenc-legacy` | DERSIG rejects a bad encoding on a signature CHECKMULTISIG tries. |
| `multisig-unused-badenc-v0` | Witness v0 skips encoding checks for a signature the multisig walk does not reach. |
| `multisig-tried-badenc-v0` | Witness v0 DERSIG rejects a bad encoding on a signature the walk tries. |
| `nulldummy-off-legacy` | Legacy CHECKMULTISIG accepts a non-empty dummy when NULLDUMMY is off. |
| `nulldummy-on-legacy` | Legacy CHECKMULTISIG rejects a non-empty dummy when NULLDUMMY is on. |
| `nulldummy-off-v0` | Witness v0 accepts a non-empty dummy when NULLDUMMY is off. The flag rejects it, not the signature version. |
| `nulldummy-on-v0` | Witness v0 rejects a non-empty dummy when NULLDUMMY is on. |
| `nulldummy-cms-tap` | Tapscript CHECKMULTISIG fails before the dummy is interpreted. |
| `nulldummy-cmsverify-tap` | Tapscript CHECKMULTISIGVERIFY fails before the dummy is interpreted. |
| `multisig-m-gt-n-v0` | Witness v0 CHECKMULTISIG rejects m > n. |

## CLTV and CSV

`OP_CLTV` and `OP_CSV` are the same opcodes in every signature version. The rows are bare scripts, plus witness v0 copies of the negative locktime, the equal height, and the version compare. A missing `spend` object keeps version 1, locktime 0, sequence `0xffffffff`, and one output. `version` is the consensus i32 bit pattern, compared as an unsigned value.

| Id | Predicate |
|----|-----------|
| `cltv-off-does-not-pop` | With CHECKLOCKTIMEVERIFY off, OP_CLTV is a NOP and does not pop. |
| `csv-off-does-not-pop` | With CHECKSEQUENCEVERIFY off, OP_CSV is a NOP and does not pop. |
| `cltv-off-negative-nop` | Flag-off OP_CLTV leaves a negative number on the stack. DROP can still remove it. |
| `csv-off-negative-nop` | Flag-off OP_CSV leaves a negative number on the stack. |
| `cltv-negative` | OP_CLTV rejects a negative locktime. |
| `csv-negative` | OP_CSV rejects a negative sequence argument. |
| `cltv-5byte-ok` | A 5-byte locktime that still fits is accepted when minimal checks are off. |
| `cltv-6byte` | A 6-byte locktime is rejected. |
| `csv-5byte-ok` | A 5-byte sequence argument that still fits is accepted when minimal checks are off. |
| `csv-6byte` | A 6-byte sequence argument is rejected. |
| `cltv-type-mismatch-time-vs-height` | A time locktime against a height locktime rejects. The threshold is 500000000. |
| `cltv-type-mismatch-height-vs-time` | A height locktime against a time locktime rejects. |
| `cltv-equal-height` | OP_CLTV accepts a height equal to the transaction locktime. |
| `cltv-greater-height` | OP_CLTV rejects a height one above the transaction locktime. |
| `cltv-equal-time` | OP_CLTV accepts a time locktime equal to the transaction locktime. |
| `cltv-greater-time` | OP_CLTV rejects a time locktime one above the transaction locktime. |
| `cltv-final-sequence` | OP_CLTV rejects a final nSequence even when the locktime matches. |
| `cltv-sequence-not-final` | OP_CLTV accepts locktime 0 when nSequence is not final. |
| `csv-disable-bit-skips-version` | The CSV disable bit succeeds and does not apply the version check. |
| `csv-version-below-2` | With the disable bit clear, a transaction version below 2 rejects. |
| `csv-version-ffffffff` | Version 0xFFFFFFFF passes the unsigned version compare. It is not below 2. |
| `csv-equal` | OP_CSV accepts a matching sequence type and value. |
| `csv-one-less` | OP_CSV rejects a sequence value one below the argument. |
| `csv-type-mismatch` | OP_CSV rejects a type-bit mismatch. |
| `csv-type-match` | OP_CSV accepts when the type bit and the value both match. |
| `csv-input-disable` | OP_CSV rejects when the input sequence has its disable bit set. |
| `cltv-negative-v0` | Witness v0 OP_CLTV rejects a negative locktime. |
| `cltv-equal-height-v0` | Witness v0 OP_CLTV accepts a matching height. |
| `csv-version-below-2-v0` | Witness v0 OP_CSV rejects version 1. |
| `csv-version-ffffffff-v0` | Witness v0 OP_CSV accepts version 0xFFFFFFFF. |

## Spend dispatch and fast paths

BIP16 and Taproot exception hashes change which scripts run. They are block-hash rules, not a `VerifyScript` row. `exception_hashes_change_which_scripts_run` pins both hashes. `corpus_fast_paths_call_typed_verifiers` calls `p2pkh::verify`, `p2wpkh::verify`, and `p2tr::verify` on the same credit and spend as these rows. A one-byte change to the P2PKH template leaves that template. A one-byte change to a P2WPKH program stays a 20-byte v0 program and misses the pubkey hash.

| Id | Predicate |
|----|-----------|
| `p2sh-on-executes-true` | P2SH on executes a push-only true redeem. |
| `p2sh-on-executes-false` | P2SH on executes a push-only false redeem and rejects it. |
| `p2sh-off-skips-false` | P2SH off checks the scriptPubKey hash only and does not execute the false redeem. |
| `p2sh-on-not-push-only` | A non-push-only scriptSig does not execute the redeem. P2SH rejects it. |
| `p2sh-off-not-push-only` | With P2SH off, a non-push-only scriptSig still runs and the hash template can accept. |
| `wit-v0-20-empty` | An empty witness on a 20-byte v0 program rejects when WITNESS is on. |
| `wit-v0-21` | A v0 program whose length is not 20 or 32 rejects. |
| `wit-v0-32-true` | A 32-byte v0 program runs the witness script. OP_1 accepts. |
| `wit-v1-33-anyone` | A v1 program of a length other than 32 is anyone-can-spend while discourage bits are off. |
| `wit-v1-33-discourage` | DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM rejects that non-32 v1 program. |
| `wit-v2-32-anyone` | A witness version above 1 is anyone-can-spend while discourage bits are off. |
| `wit-v2-32-discourage` | DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM rejects a witness version above 1. |
| `p2pkh-fast-ok` | Exact P2PKH scriptSig takes the typed verifier and accepts. |
| `p2pkh-fast-mutated` | Changing one template byte drops P2PKH. The bare script rejects. |
| `p2pkh-fad-collision` | A signature push equal to the 20-byte pubkey hash is not a verifying signature. Both engines reject it. |
| `p2wpkh-fast-ok` | Native P2WPKH takes the typed verifier and accepts. |
| `p2wpkh-fast-mutated` | Changing one program byte makes the pubkey hash miss. P2WPKH rejects. |
| `p2tr-keypath-ok` | A 32-byte v1 key path takes the typed taproot verifier and accepts. |
| `p2tr-keypath-mutated` | Changing one output-key byte makes the key path miss. |
| `tapleaf-unknown-521` | An unknown tapleaf version succeeds without running the leaf, so a 521-byte element is ignored. |
| `tapleaf-unknown-1001` | An unknown tapleaf version succeeds without running the leaf, so 1001 stack items are ignored. |
| `tapleaf-known-521` | A known tapscript leaf rejects a 521-byte element. |
| `tapleaf-known-1001` | A known tapscript leaf rejects 1001 stack items. |
| `p2sh-witness-unexpected` | A non-empty witness on a legacy P2SH redeem is rejected. |
| `p2sh-witness-empty-script` | P2SH with an empty scriptSig does not execute a redeem. WITNESS does not change that. |
| `p2wpkh-low-s-witness-len` | LOW_S sends P2WPKH through the interpreter, which still rejects a one-item witness. |
| `checksigverify-empty-32-tap` | Tapscript CHECKSIGVERIFY rejects an empty signature for a 32-byte key. |
| `schnorr-bad-len-tap` | A tapscript signature that is neither 64 nor 65 bytes fails CHECKSIG. |
