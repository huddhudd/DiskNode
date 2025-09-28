# UserDisk parity review

## Fixed bug
- The Windows reference handler `HiPullList` responds with a 404 (`code=2`) whenever the cached `.list` file cannot be read or is empty, while the Go `handleUserDiskList` previously returned a 500 for read failures and served empty payloads. The handler now mirrors the reference for unreadable lists but keeps empty lists as a successful empty response to align with expected client behaviour.【F:nvservice/server/userdisk.go†L162-L210】【F:UserDisk.cpp†L38-L76】
- The `/UserDisk/check_files` endpoint now enforces the `size` query just like `HiCheckFile`, rejecting missing or mismatched lengths with HTTP 405 (`code=2`) and treating empty bodies as `code=1`. This prevents truncated uploads from slipping through and surfaces parity with the Windows contract.【F:nvservice/server/userdisk.go†L336-L356】【F:UserDisk.cpp†L300-L318】

## Outstanding gaps

### Cleanup behaviour and list maintenance
- The Windows implementation ages files by rewriting timestamps, records hashes that need list updates, and purges obsolete lists based on their last access time inside `DiskClearup`/`DiskListClearup`. The Go `runUserDiskCleanup` simply deletes files older than the cutoff and only updates lists for hashes it physically removed, leaving no pathway to mirror the staged cleanup/tag counters or to delete idle list files by timestamp.【F:nvservice/server/userdisk.go†L838-L921】【F:nvservice/server/userdisk.go†L755-L818】【F:UserDisk.cpp†L574-L720】【F:UserDisk.cpp†L732-L816】
