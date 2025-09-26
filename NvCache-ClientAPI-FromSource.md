# NvCache Client API (from source)

本文件依据源码 Z:\qihao\CloudApp\UserDoc\UserDocServer\NvCache.cpp NvCache.h 整理，修正并补全了客户端可用的 NvCache HTTP 接口定义、请求与响应细节、错误码及典型流程。

更新日期：2025-08-17

## 总览
- 基础路径：/NvCache/
- 角色：管理着色器/缓存类去重文件及其清单（Binary FileList）
- 主要接口（4个）：
  1) GET /NvCache/list
  2) POST /NvCache/check_files
  3) POST /NvCache/upload_file  （支持一次性上传或“分片完成”提交）
  4) POST /NvCache/upload_list  （上报清单增量）

约定与通用规则：
- 所有字符串按 UTF-8 处理，URL 查询参数需按 URL 编码。
- 所有带有 size 查询参数的接口，会严格校验 size == 请求体字节数，不一致则返回错误。
- SHA1 hash 必须为 40 位十六进制字符串（大小写均可，内部按小写处理）。
- 正常 JSON 响应以 {"code":0,"msg":"ok"} 为基准；错误时 code != 0，并配合 4xx/5xx HTTP 状态码。
- Binary FileList 的具体二进制结构由客户端按既有协议解析（服务端 Content-Type: stream/fileslist）。

服务端请求处理总览（仅服务端）：
- 路由前缀：/NvCache/
- 入口：CNvCache::httpProcess
  - list      -> CNvCache::HiPullList（拉取清单，内部先合并 queue）
  - check_files -> CNvCache::HiCheckFile（校验 hash 是否已存在于缓存）
  - upload_file -> CNvCache::HiUploadFile（保存哈希对象，支持分片完成提交流程）
  - upload_list -> CNvCache::HiUploadList（将增量 JSON 以 "$\r\n" 片段追加到 name.queue）
- 周期任务：
  - CNvCache::NvClearup(std::set<std::string> const& onlineSeats)
    - 合并积压的 *.queue
    - 清理离线 seat（回收 seat.list 的 RefCount 并删除 seat.list）
    - 清理 RefCount<=0 的哈希对象与相应数据库条目
  - CNvCache::NvClearup(int KeepDays)
    - 清理过期 *.list（按访问时间）并回收其 RefCount
    - 清理 NVCC_PREFIX 下过期/非法文件与目录

---

## 1) 拉取清单 GET /NvCache/list
- 路径：/NvCache/list
- 方法：GET
- 查询参数：
  - seat: string，必填。机器唯一标记（例如计算机名）。
  - name: string，必填。清单名称（建议“显卡名称 + 启动版本号”等）。
- 请求体：无

处理逻辑（要点）：
- 服务端把 name 映射到 name.list 与 name.queue（队列增量）。
- 如存在 name.queue，会将其合并进 name.list（原子替换）。
- 为 seat 维护一个 seat 专属的副本清单（SEAT/seat.list），用于引用计数增减。
- 若新旧清单签名（md5/ver）相同，直接返回缓存清单；否则生成新清单、更新引用计数并原子替换。

成功响应：
- 200 OK，Content-Type: stream/fileslist
- Body：二进制清单数据（CACHE_CONTEXT + 条目）

失败响应（示例）：
- 405 {"code":1,"msg":"Bad params"}：seat 或 name 缺失/为空；

### 服务端内部：HiPullList 详细流程
```mermaid
flowchart TD
  A[收到 GET /NvCache/list?seat&name] --> B{参数校验}
  B -->|seat/name 空| E1[405 code:1 Bad params]
  B -->|通过| C[将 name 转小写; 拼接 name.list/name.queue 路径]
  C --> D[加 RW 锁; 调用 ProcessQueueFile 合并队列]
  D --> E{读取 seat.list 旧清单}
  E -->|失败且非 not found| E2[500 code:5 read error]
  E --> F{新旧清单签名一致?}
  F -->|是| G[直接返回 stream/fileslist]
  F -->|否| H[写 name.tmp; 计算 hashInc/hashDec]
  H -->|失败| E3[500 code:6/7/8]
  H --> I[开始事务; 执行引用计数增减]
  I -->|失败| E4[500 code:10/11]
  I --> J[原子重命名 .tmp -> seat.list]
  J -->|失败| E5[500 code:11]
  J --> K[COMMIT; 返回 stream/fileslist]
```

实现要点：
- name.queue 合并通过 ProcessQueueFile：将多段 JSON 以“]$\r\n[”连接的队列展开为一个数组并解析。
- 引用计数：通过旧/新清单差异（hashDec/hashInc）批量进行计数 +1/-1。
- 原子替换 seat.list：使用 FileDispositionInfo + ZwSetInformationFile(rename) 语义。

- 404 {"code":2,"msg":"Not Found"}：清单不存在；
- 500 {"code":5,"msg":"read error"}：读取 seat.list 失败（非不存在）；

### 服务端内部：HiCheckFile 详细流程
```mermaid
flowchart TD
  A[收到 POST /NvCache/check_files?size] --> B{size 与 body 长度一致}
  B -->|否| E1[405 code:2 invalid data len]
  B -->|是| C[解析 JSON 数组]
  C --> D[遍历每个 hash: 合法性校验]
  D -->|非法| SKIP[忽略并记录错误日志]
  D -->|合法| E[拼哈希路径; 检查是否存在]
  E -->|不存在| F[加入响应 files 列表]
  E -->|存在| NOP[不加入]
  F --> G[序列化响应]
  NOP --> G
  SKIP --> G
  G --> H[返回 200 JSON]
```
实现要点：

### 服务端内部：HiUploadFile 详细流程
```mermaid
flowchart TD
  A[收到 POST /NvCache/upload_file] --> B{是否带 chunked}
  B -->|否·一次性上传| C1[读取 size 与 body; 计算 SHA1]
  C1 --> D1{SHA1 == hash}
  D1 -->|否| E1[405 code:4 Invaild hash]
  D1 -->|是| F1[保存到哈希路径; 若存在视为成功]
  F1 --> G1[200 code:0 ok]

  B -->|是·分片完成| C2[根据 chunked 名获取临时大文件]
  C2 -->|未找到| E2[405 code:11 file not found]
  C2 --> D2[计算临时文件 SHA1]
  D2 -->|不等于 hash| E3[405 code:14 Invaild hash]
  D2 -->|相等| F2{目标哈希对象已存在}
  F2 -->|是| G2[200 code:0 exist 并删除临时]
  F2 -->|否| H2[原子重命名为哈希对象]
  H2 -->|失败| E4[500 code:13 文件重命名失败]
  H2 --> G3[200 code:0 ok]
```
实现要点：
- 一次性上传路径：严格校验 size 和 SHA1；
- 分片完成路径：仅做校验与提交，分片过程由其他模块负责；
- 若目标已存在，返回 exist/ok，客户端可视为成功（幂等）。

- hash 必须 40 位十六进制；
- 存在性检查走本地缓存（NVCC_PREFIX）映射；
- 响应仅包含“缺失”的 hash。

- 500 {"code":6,"msg":"write error"}：写入 .tmp 失败；
- 500 {"code":7|8,"msg":"parse list error"}：清单解析失败；
- 500 {"code":10|11,"msg":"database failed"}：引用计数更新或重命名失败。

示例：
GET /NvCache/list?seat=pc-A010&name=RTX4060_1.2.3

---

## 2) 检查缺失文件 POST /NvCache/check_files
- 路径：/NvCache/check_files
- 方法：POST
- 查询参数：
  - size: uint64，必填。请求体字节数。
- 请求体（application/json）：数组，每项格式：{"hash":"<40hex>"}

示例请求体：
[
  {"hash":"0b0bd88b6b2901c047b8c223ae5c51236c2f79f1"},
  {"hash":"040bd88b6b2901c047b8c223ae5c51236c2f7134"}
]

处理逻辑：
- 校验 size 与实际字节数一致；校验每个 hash 格式合法；
- 返回“服务端不存在”的 hash 列表（需要上传）。

成功响应：
- 200 {"code":0,"msg":"ok","files":[{"hash":"..."}, ...]}

失败响应（示例）：
- 405 {"code":1,"msg":"Bad Request"}：无请求体；
- 405 {"code":2,"msg":"invalid data len"}：size 与实际不一致；
- 405 {"code":4,"msg":"Bad Request"}：请求体非合法 JSON。

---

## 3) 上传文件 POST /NvCache/upload_file
支持两种用法：一次性上传，或“分片完成”提交。

### 3.1 一次性上传
- 路径：/NvCache/upload_file
- 方法：POST
- 查询参数：
  - hash: string，必填，40位 SHA1 hex；
  - size: uint64，必填，请求体字节数。
- 请求体：二进制文件原始数据（raw）。


### 服务端内部：HiUploadList 详细流程
```mermaid
flowchart TD
  A[收到 POST /NvCache/upload_list?name&size] --> B{参数校验}
  B -->|name 空| E1[405 code:3 Bad params]
  B -->|size 不匹配| E2[405 code:2 invalid data len]
  B -->|通过| C[将 name 转小写; 生成 name.queue 路径]
  C --> D[以 FILE_APPEND 方式打开/创建 name.queue]
  D -->|失败| E3[500 code:4 Internal Server Error]
  D --> E[在末尾追加 JSON 片段与分隔符]
  E -->|失败| E4[500 code:5 Internal Server Error]
  E --> F[返回 200 JSON]
```
实现要点：
- 不直接合并，延后到 HiPullList 或后台清理统一处理，降低并发冲突。
- 多批次队列格式：服务端后续以“]$\r\n[”替换为逗号，串接为一个大的 JSON 数组再解析。

处理逻辑：
- 校验 hash 格式；校验 size；对请求体计算 SHA1 必须与 hash 一致；
- 将文件保存为哈希路径对象（存在则直接视为成功）。

成功响应：
- 200 {"code":0,"msg":"ok"}

失败响应（示例）：
- 405 {"code":1,"msg":"Bad Request"}：hash 缺失/非法；
- 405 {"code":2,"msg":"invalid data len"}：size 不一致；
- 405 {"code":4,"msg":"Invaild hash"}：内容 SHA1 与 hash 不一致；
- 500 {"code":5,"msg":"Save file failed(0x...)"}。

### 3.2 分片完成提交
- 路径：/NvCache/upload_file
- 方法：POST
- 查询参数：
  - hash: string，必填，40位 SHA1 hex；
  - chunked: string，必填，会话名/临时大文件标识。
- 请求体：无（或空）。

处理逻辑：
- 按 (chunked, hash) 找到已上传的临时大文件；计算其 SHA1 与 hash 必须一致；
- 若目标哈希对象已存在：返回 exist 并删除临时文件；否则原子重命名为目标对象。

成功响应：
- 200 {"code":0,"msg":"ok"} 或 {"code":0,"msg":"exist"}

失败响应（示例）：
- 405 {"code":11,"msg":"file not found"}：未找到会话文件；
- 405 {"code":14,"msg":"Invaild hash"}：临时文件 SHA1 与 hash 不一致；
- 500 {"code":13,"msg":"file rename failed 0x..."}。

---

## 4) 上报清单增量 POST /NvCache/upload_list
- 路径：/NvCache/upload_list
- 方法：POST
- 查询参数：
  - name: string，必填，清单名称；
  - size: uint64，必填，请求体字节数。
- 请求体（application/json）：数组，元素为以下两种之一：
  - 增加 add：
    {
      "add": {
        "hash": "40hex",           // 文件时必填；目录可不填
        "path": "relative\\path", // 必填，相对路径
        "size": 123,                 // 文件大小

## 服务端周期任务与内部清理（仅服务端）

### 在线 seat 管理与清理（NvClearup(onlineSeats)）
```mermaid
flowchart TD
  A[触发 NvClearup onlineSeats] --> B[扫描 队列文件 并合并到 list]
  B --> C[刷新在线 seat 集合: onlineSeats]
  C --> D{遍历 m_mSeat}
  D -->|seat 不在线| E[加入待清理列表]
  D -->|seat 在线| F[更新 seat.LastCheckTime]
  E --> G[对于待清理 seat]
  G --> H[读取 seat.list 旧清单]
  H --> I[计算 hashDec 自 seat.list]
  I --> J[开始事务; 执行引用计数减少]
  J -->|失败| E1[ROLLBACK 并跳过]
  J --> K[删除 seat.list]
  K --> L[COMMIT]
```

实现要点：
- “在线”判断依赖调用方传入的 onlineSeats（通常由上层连接管理获得）；
- 对长时间不在线的 seat 执行回收：将其 seat.list 中的引用全部 -1，删 seat.list；
- 日志聚合输出清理结果（文件计数、失败统计等）。

### 无参清理（NvClearup(KeepDays)）
```mermaid
flowchart TD
  A[触发 NvClearup KeepDays] --> B[扫描 清单目录 下的 list 文件]
  B --> C{最近访问时间超阈值?}
  C -->|否| B
  C -->|是| D[解析旧 list, 获得 hashDec]
  D --> E[开始事务; 执行引用计数减少]
  E -->|失败| E1[ROLLBACK]
  E --> F[删除该 *.list]
  F --> G[COMMIT]
  G --> H[递归扫描 NVCC_PREFIX]
  H --> I{目录/文件是否合法/过期?}
  I -->|非法或过期| J[删除目录/文件]
  I -->|合法| K[跳过]
```

实现要点：
- KeepDays 计算清单保留期（源代码取 KeepDays/2）；
- 删除 *.list 前先回收其引用计数；
- NVCC_PREFIX 下仅保留二级16进制目录与 40hex 文件，其它会被删除；
- 针对 RefCount<=0 的哈希文件，尝试物理删除并清理数据库记录。

        "attr": 32,                  // Windows 文件属性（目录请包含 FILE_ATTRIBUTE_DIRECTORY）
        "time": 13345788111235454    // 文件时间（单位：100ns tick）
      }
    }
  - 删除 del：
    {"del":{"name":"relative\\path"}}

处理逻辑：
- 服务端将该 JSON 末尾追加 "$\r\n" 并以“追加”方式写入 name.queue；
- 真正合并发生在 /NvCache/list（或后台清理）阶段：
  - 解析队列，把 add/del 应用到现有清单；
  - 对 add 的文件，会检查哈希对象是否存在，不存在则忽略并警告；
  - 对 hash 引用计数进行增减；
  - 原子替换 name.list。

成功响应：
- 200 {"code":0,"msg":"ok"}

失败响应（示例）：
- 405 {"code":1,"msg":"Bad Request"}：无请求体；
- 405 {"code":2,"msg":"invalid data len"}：size 不一致；
- 405 {"code":3,"msg":"Bad params"}：name 为空；
- 500 {"code":4|5,"msg":"Internal Server Error"}：打开/写入 .queue 失败。

### 请求/响应字段详解（补充）
- seat（string）：客户端“席位”标识。服务端为每个 seat 维护独立的 seat.list，用于引用计数的增减。
- name（string）：清单主名，映射 name.list 与 name.queue。
- size（uint64）：HTTP 请求体字节数。所有带 size 的接口服务端都会严格校验。
- hash（40hex）：SHA1 校验值，大小写均可（内部小写）。
- path（string）：相对路径，清单条目路径；删除时用 name 字段指明。
- attr（uint32）：Windows 文件属性；目录应包含 FILE_ATTRIBUTE_DIRECTORY。
- time（int64）：文件时间，单位为 100ns tick（源码使用 FILETIME 相关转换）。
- Content-Type：
  - stream/fileslist：二进制清单；
  - application/json：JSON 响应。

### 客户端重试与幂等建议
```mermaid
flowchart TD
  R0[网络/服务不稳定] --> R1[幂等性策略]
  R1 --> R2[check_files 可安全重试]
  R1 --> R3[upload_file 可安全重试]
  R3 -->|已存在| R3S[返回 exist/ok]
  R1 --> R4[upload_list 建议批量且避免重复]
  R4 -->|重复增| R4E[最终以 last-write 为准]
  R1 --> R5[list 可安全重试]
```

要点：
- check_files：读取型，重试安全；
- upload_file：按 hash 去重，若服务器已存在，同样返回成功语义（exist/ok），重试安全；
- upload_list：建议客户端对同一批次的增量去重后再提交，避免重复 add/del；
- list：读取型，重试安全；
- 建议对 5xx 使用指数退避重试，405/4xx 需修正参数后再发。

### 服务器引用计数与 seat 交互（深入）
```mermaid
sequenceDiagram
  participant Seat as Seat(客户端)
  participant Srv as Server
  Seat->>Srv: GET /NvCache/list?seat=...&name=...
  Note over Srv: 1) 读取 name.list + 合并 name.queue
  Srv-->>Seat: stream/fileslist
  Note over Srv: 2) 比较 seat.list 与新清单，计算 hashInc/hashDec
  Srv-->>Srv: 更新数据库 RefCount(+/-)
  Srv-->>Srv: 原子替换 seat.list
```


---

## 典型流程图（Mermaid）
以下 Mermaid 定义可直接渲染为流程图（建议使用 mermaid-cli 或 VSCode 插件）。

```mermaid
flowchart TD
  A[客户端启动] --> B[GET /NvCache/list]
  B -->|存在清单| C[使用清单]
  B -->|404 Not Found| C
  C --> D[本地扫描变更]
  D --> E[POST /NvCache/check_files]
  E -->|返回缺失hash| F[逐个 POST /NvCache/upload_file]
  F --> G[POST /NvCache/upload_list]
  G --> H[GET /NvCache/list]
  H --> I[得到合并后的最终清单]
```

### 端到端详细流程（含分支与错误处理）
```mermaid
flowchart LR
  subgraph Client
    SCAN[扫描本地变更]
    CF[check_files]
    UF[上传缺失文件 upload_file]
    UL[上传清单 upload_list]
    GL[获取清单 list]
  end
  subgraph Server
    CHK[处理 check_files]
    UPF[保存/验证哈希对象]
    Q[queue 追加 name.queue]
    M[合并 queue 到 name.list]
    RC[引用计数增减]
    SL[seat.list 原子替换]
    RET[返回 stream/fileslist]
  end

  SCAN --> CF
  CF -->|POST /NvCache/check_files| CHK
  CHK -->|200 files: 缺失hash列表| CF
  CF -->|for each 缺失hash| UF
  UF -->|POST /NvCache/upload_file| UPF
  UPF -->|200 ok/exist 或 4xx/5xx| UF
  UF --> UL
  UL -->|POST /NvCache/upload_list| Q
  Q --> GL
  GL -->|GET /NvCache/list| M
  M --> RC --> SL --> RET
  RET --> GL

  %% 错误分支
  CF -.->|405/size 不一致| CF
  UF -.->|405 Invaild hash| UF
  UL -.->|405/500 queue 写入失败| UL
  GL -.->|404 Not Found| GL
  GL -.->|500 parse/database 失败| GL
```

### 合并与生成清单内部过程（服务端视角）
```mermaid
flowchart TD
  Q{name.queue 是否存在} -->|是| P[读取并拼接 queue 片段]
  Q -->|否| USE[保持 name.list 不变]
  P --> J[解析 JSON 数组]
  J -->|add 文件| CK[检查 hash 对象是否存在]
  CK -->|存在| ADD[添加/更新文件项]
  CK -->|不存在| IGNORE[忽略并记录警告]
  J -->|add 目录| ADDF[添加目录项]
  J -->|del 路径| DEL[删除项]
  ADD --> L[重建 ListContent]
  ADDF --> L
  DEL --> L
  L --> RC[计算 hashInc/hashDec 引用差异]
  RC --> DB[更新数据库 RefCount]
  DB --> RENAME[.tmp 原子替换 name.list]
  RENAME --> DONE[完成]
```


### 上传文件（一次性）与检查缺失（时序图）
```mermaid
sequenceDiagram
  participant Cli as Client
  participant Srv as Server (/NvCache)
  Cli->>Srv: POST /check_files (size, body=[{hash}...])
  Srv-->>Cli: 200 { code:0, files:[{hash}...] }
  loop for each missing hash
    Cli->>Srv: POST /upload_file?hash=...&size=... (raw body)
    Srv-->>Cli: 200 { code:0, msg:"ok" }
  end
  Cli->>Srv: POST /upload_list?name=...&size=... (add/del 数组)
  Srv-->>Cli: 200 { code:0, msg:"ok" }
  Cli->>Srv: GET /list?seat=...&name=...
  Srv-->>Cli: 200 stream/fileslist (最终清单)
```

---

## 错误码速查
- 1: Bad params / Bad Request（参数缺失或请求体缺失/非法）
- 2: invalid data len（size 与实际字节数不一致）
- 3: Bad params（upload_list 的 name 缺失）
- 4: Invaild hash / Bad Request（hash 校验失败或 JSON 非法）
- 5: read/write/Save file failed（具体见接口）
- 6: write error（list .tmp 写失败）
- 7/8: parse list error（清单解析失败）
- 10/11: database failed（引用计数或文件重命名失败）
- 13: file rename failed（分片完成阶段）
- 14: Invaild hash（分片完成阶段 sha1 不一致）

---

## 备注
- 服务端内部还包含定期清理与 seat 在线状态管理，不影响客户端 API 的使用方式。
- 若采用分片上传，分片的“合并”不在本文接口范围内；/upload_file?chunked= 会话名 仅负责将合并结果提交为最终对象。

