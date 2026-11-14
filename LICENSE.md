# LICENSE

This project is licensed under the **Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)** license.

## 📌 Summary (non-legally binding)

This license includes the following terms:

- **Attribution (BY)** – You must give appropriate credit to the original authors.
- **NonCommercial (NC)** – You may not use the material for commercial purposes without explicit permission.
- **ShareAlike (SA)** – If you remix, transform, or build upon the material, you must distribute your contributions under the same license.

## ✅ What does this mean in practice?

- You may use, copy, modify, and share the contents of this project **for personal, educational, or research purposes**.
- You must always credit the original author when using or sharing it.
- You may not sell, commercialize, or integrate the material into proprietary systems without written consent.
- If you publish modified versions, they must also be licensed under CC BY-NC-SA 4.0.

## 📄 Full legal text

For the full legal license, visit:  
[https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode](https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode)

## © Copyright and Attribution

© 2025 Sinkó Gábor Zoltán / OpenIntentSign / CentralInfraCore  
All rights reserved, except as explicitly permitted by the license above.

## Exception: commit-signing toolchain (MIT)

The following files are licensed under the **MIT License**
([`LICENSES/MIT.txt`](LICENSES/MIT.txt)), not under CC BY-NC-SA 4.0. Each
carries `SPDX-License-Identifier: MIT`.

```
tools/git_hook_commit-msg.sh        tools/test-commit-msg-signer.sh
tools/lib-vault-sign.sh             tools/test-verify-signatures.sh
tools/verify-signatures.sh          tools/test-resign-on-rebase.sh
tools/lib-tag-manifest.sh           tools/test-proof-binding.sh
tools/sign-release-tag.sh           tools/test-check-hook-provenance.sh
tools/resign-range.sh               tools/test-sign-release-tag.sh
tools/git_hook_post-rewrite.sh
tools/check-hook-provenance.sh
tools/init-hooks.sh
tools/measure-rebase-signatures.sh
```

**Why MIT here.** Every repository is created from this template, partner
modules included. A NonCommercial or copyleft licence on the signing hook would
follow into every repository that signs its commits with it.

**Provenance and basis for the dual licence.** The same code is published in
[`cic-factory-core`](https://github.com/CentralInfraCore/cic-factory-core)
under AGPL-3.0-or-later (taken from its `feature/signer-key-in-manifest` branch,
commit `3e1b60f`; the files here differ from that commit only in the
`SPDX-License-Identifier` line). The copyright holder of both is
Sinkó Gábor Zoltán / CentralInfraCore, as stated in each file's
`SPDX-FileCopyrightText`. As the holder of both, Sinkó Gábor Zoltán licenses
this code under MIT here in addition to AGPL-3.0-or-later there; neither licence
restricts the other.

Authorship was checked against the full history of these 16 files in
`cic-factory-core` (`git log --full-history`, 21 commits): 20 are authored as
Gábor Z Sinkó or Gábor Zoltán Sinkó. The remaining one, `39dad9a` (2026-06-06),
was made under an unconfigured git
identity (`Your Name <you@example.com>`); it added `tools/git_hook_commit-msg.sh`
and `tools/init-hooks.sh` as byte-identical copies of this repository's own
commits `5bf20fb` and `0f16d9f` (Gabor Sinkó, 2025-12-02). No third-party code
is included; the third-party MIT code in `cic-factory-core` (`tools/hooks/`,
yurukusa) was not brought over.
