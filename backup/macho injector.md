简单复刻 Coruna macho injector，尝试在越狱环境下不通过 `dlopen` 把 Mach-O 映射进目标进程。
测试环境：`iPhone X`-`arm64`-`16.7.16` / Dopamine，目标 SpringBoard。

## 流程

```text
task_for_pid
    │
    ▼
本地读 Mach-O（segment / _last / LC_DYLD_CHAINED_FIXUPS）
    │
    ▼
mach_vm_allocate → 拷段 → rebase/bind → mach_vm_write
    │
    ▼
mach_vm_protect（__TEXT=RX，数据段=RW）
    │
    ▼
bootstrap → pthread_create_from_mach_thread(_last)
```

和远程 `dlopen` 的差别：装载与 fixup 由 injector 完成，dyld 不参与。

## Target

`pid / 进程名 → task_for_pid → task port`

获取到目标进程的 `task` 后，对目标地址空间可：`mach_vm_allocate` / `mach_vm_read` / `mach_vm_write` / `mach_vm_protect` / `thread_create`。

权限通常需要 `task_for_pid-allow`；目标是 SpringBoard 这类 platform 进程还要 `com.apple.system-task-ports`。
远程 `thread_set_state` 另需 `com.apple.private.thread-set-state`，否则 injector 会 `EXC_GUARD`。

- **远程符号（已加载镜像）**

bind `_dlsym`、起 pthread 都要目标进程里的真实 VA，不能用 injector 自己的地址。做法是读目标 dyld 镜像表，再扫符号表：

```text
task_info(TASK_DYLD_INFO) → all_image_info_addr
    │
    ▼
dyld_all_image_infos.infoArray[]
    │  每项：imageLoadAddress + imageFilePath
    ▼
find_remote_image(needle)     // 路径 substring，如 "/libdyld.dylib"
    │
    ▼
remote_dlsym(header, "_dlsym")
    │  slide = header - __TEXT.vmaddr
    │  读 LC_SYMTAB + __LINKEDIT → nlist_64
    ▼
runtime = n_value + slide
```

## Payload

只留一个 undefined(_dlsym)，其余运行时解析：

- 导出 `_last(void *)`（pthread 入口）
- 唯一 import：`_dlsym`
- `open` / `write` / … → `_dlsym(RTLD_DEFAULT, "…")`

构建：`-Wl,-fixup_chains`、`-fno-builtin`、只导出 `_last`。

injector 在目标 `libdyld` 里解析 `_dlsym`，填进 bind 槽即可。

## Chained Fixups

现代 Mach-O 用 `LC_DYLD_CHAINED_FIXUPS`，不再走老式 rebase/bind opcode 流。磁盘上某些 8 字节槽位是**编码**，加载时要改成运行时指针。

两类：

| | rebase | bind |
|--|--------|------|
| 含义 | 本镜像内指针 | 外部符号 |
| 编码 | `bind=0`，带 target / next | `bind=1`，带 ordinal / addend / next |
| 结果 | 按 slide（或 runtimeOffset）算出地址 | ordinal → imports → 符号真实地址 |

- **blob**

```text
[dyld_chained_fixups_header]
    starts_offset  → 每 segment 的 page_start[]（链表入口）
    imports_offset → import 数组（ordinal → 名字）
    symbols_offset → 符号名字符串池
```

`seg_info_offset` 下标必须与 `LC_SEGMENT_64` 顺序一致（含 `__PAGEZERO`）。

- **slide / remote_base**

```text
preferred_vmin = 非 __PAGEZERO 各 segment 的最小 vmaddr（链接时地址空间起点，dylib 常为 0）
remote_base    = 目标进程里 mach_vm_allocate(VM_FLAGS_ANYWHERE) 返回的实际基址

slide          = remote_base - preferred_vmin
```

preferred_* 来自文件；`remote_base` 由内核在目标 VA 里现挑，每次可能不同。

- **arm64**

同一 64bit 按 `bind` 位解释成 rebase 或 bind 结构：

```text
rebase:
  DYLD_CHAINED_PTR_64:        runtime = slide + target          // target = preferred vmaddr
  PTR_64_OFFSET: runtime = remote_base + target    // target = 相对镜像基址偏移

bind:
  ordinal → imports[ordinal].name
         → 目标进程符号地址 + addend
```

**addend**：链接器在绑定记录（Binding Record）里携带的“额外偏移”被称为 Addend；

本 demo 的 bind 只接受 `_dlsym`：在目标 `libdyld` 里解析一次，写入所有 bind 槽。

- **链表**

同一页内多个待改指针用 `next` 串起来，不是扫全页：

```text
for each segment:
  for each page:
    next = page_start[page]       // NONE 则跳过
    while true:
      slot = page_va + next
      decode raw → rebase 或 bind → 写回普通 64 位指针
      if next_field == 0: break
      next += next_field * stride // PTR_64: stride = 4
```

走完后 buffer 里已是「装载后的镜像」，再 `mach_vm_write` 进目标。

测试日志 `rebase=0 bind=1` 正常：payload 几乎 PIC，只有一条 `_dlsym` bind。

## 远程 pthread

直接 `thread_create` 跳 `_last` 缺 TLS。用目标里的 `_pthread_create_from_mach_thread`：

```text
1. 分配 code 页 + stack
2. 写 bootstrap：x0=slot, x1=0, x2=_last, x3=arg, x8=pthread_cfm; blr x8
3. thread_create → thread_set_state(pc=boot) → thread_resume
4. bootstrap 创建 pthread，start_routine = _last
```

`pthread_t *slot` 必须可写，放在 RW 栈上，不能和 RX bootstrap 同页。

## Reference

- [opainject](https://github.com/opa334/opainject)