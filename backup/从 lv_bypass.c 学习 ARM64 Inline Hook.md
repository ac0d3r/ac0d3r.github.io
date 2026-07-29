说明：_本文基于 `lv_bypass.c` 与实机 hook 日志整理，部分表述与图示由 AI 辅助生成；技术结论以源码与实测为准。_

---

## Inline Hook
Inline hook 的核心很简单：改目标函数开头几条指令，让执行流跳到你的函数。直接改代码段，对静态链接、内部调用、dyld 内部函数同样有效。

## dyld 

dyld 加载库时会做`Library Validation（LV）`：
- `F_ADDFILESIGS_RETURN`（97）：从同一文件挂上代码签名；成功时在结构体里返回 end offset
- `F_CHECK_LV`（98）：检查 LV 是否允许把该 Mach-O 映射进当前进程

未签名/签名不匹配的 dylib 会加载失败。

`lv_bypass.c` 通过 inline hook 拦截 dyld 中的 `mmap/fcntl` 路径，从而可以 dlopen 未签名的库：

```txt
dlopen(未签名 dylib)
          │
          ▼
     dyld 内部校验路径
          │
          ├─ 内部 fcntl(F_CHECK_LV/ADDFILESIGS) ──inline hook──► hooked___fcntl（放行）
          │
          └─ 内部 mmap(PROT_EXEC) ────────────────inline hook──► hooked_mmap（匿名拷贝 + mprotect）
          │
          ▼
     加载成功
```

## 逐步分析

- hook 跳板
```c
static const char patch[] = {0x88, 0x00, 0x00, 0x58,  // #0  ldr x8, #0x10  # 从本stub +16 读8字节到 x8
                             0x00, 0x01, 0x1f, 0xd6,  // #4  br x8          # 无条件跳到 x8 
                             0x1f, 0x20, 0x03, 0xd5,  // #8  nop
                             0x1f, 0x20, 0x03, 0xd5,  // #12 nop
                             0x41, 0x41, 0x41, 0x41,  // #16 占位            # hook 目标地址（运行时写入）
                             0x41, 0x41, 0x41, 0x41};
```
这是最经典的绝对跳转：不依赖当前位置相对偏移，任意地址都能跳。
代价是覆盖函数原始指令，且本实现没有保存被覆盖的原指令——调用原函数靠事先保存的函数指针（如 `__fcntl`/`__mmap`）。

- 搜索指令
```c
char *dyldBase = (char *)_alt_dyld_get_all_image_infos()->dyldImageLoadAddress; // 获得 dyld 镜像基址
searchAndPatch("dyld_mmap", dyldBase, mmapSig, sizeof(mmapSig), hooked_mmap);
searchAndPatch("dyld_fcntl", dyldBase, fcntlSig, sizeof(fcntlSig), hooked___fcntl);
...
static bool searchAndPatch(char *name, char *base, const char *signature,
                           int length, void *target) {
  char *patchAddr = NULL;
  for (int i = 0; i < 0x80000; i += 4) {
    if (base[i] == signature[0] &&
        builtin_memcmp(base + i, signature, length) == 0) {
      patchAddr = base + i;
      break;
    }
  }
  ...
  return redirectFunction(name, patchAddr, target);
}
```

在 dyld 镜像中遍历 mmap 和 fcntl 的汇编指令，找到后对该地址做patch
```c
static const char mmapSig[] = {0xB0, 0x18, 0x80, 0xD2,  // mov x16, #0xc5
                               0x01, 0x10, 0x00, 0xD4}; // svc #0x80
static const char fcntlSig[] = {0x90, 0x0B, 0x80, 0xD2, // mov x16, #0x5c
                               0x01, 0x10, 0x00, 0xD4}; // svc #0x80
```

- patch

```c
static bool redirectFunction(char *name, void *patchAddr, void *target) {
  kern_return_t kret = builtin_vm_protect(
      _mach_task_self_, (vm_address_t)patchAddr, sizeof(patch), false,
      PROT_READ | PROT_WRITE | VM_PROT_COPY);
...
  builtin_memcpy((char *)patchAddr, patch, sizeof(patch));
#if __arm64e__
  *(void **)((char *)patchAddr + 16) = __builtin_ptrauth_strip(target, 0);
#else
  *(void **)((char *)patchAddr + 16) = target;
#endif

  kret = builtin_vm_protect(_mach_task_self_, (vm_address_t)patchAddr,
                            sizeof(patch), false, PROT_READ | PROT_EXEC);
...
}
```
1. 先将代码页改成可写：代码页默认 RX，不能直接写 → 先 `vm_protect` 成 RW。共享映射往往拿不到写权限，所以加上 `VM_PROT_COPY`（`0x10`）：把该 entry 标成 needs copy，按 COW 复制对象，并在最大保护里加上写权限，之后才能往本进程私有页上写 stub。
2. 写入 stub + 目标地址（arm64e：指针带 PAC，写入前用 `__builtin_ptrauth_strip` 去掉签名）。
3. 写完立刻改回 RX，否则后续执行会出问题。

- hook_map

```c
static void *hooked_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  void *map = __mmap(addr, len, prot, flags, fd, offset);
  if (map == MAP_FAILED && fd && (prot & PROT_EXEC)) {
    map = __mmap(addr, len, PROT_READ | PROT_WRITE,
                 flags | MAP_PRIVATE | MAP_ANON, 0, 0);
    void *memoryLoadedFile =
        __mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, offset);
    builtin_memcpy(map, memoryLoadedFile, len);
    _munmap(memoryLoadedFile, len);
    _mprotect(map, len, prot);
  }
  return map;
}
```
dyld 加载 `Mach-O` 时，会对 `__TEXT` 一类段做“从文件映射 + 可执行”的 `mmap`，权限里带 `PROT_EXEC`，且 `fd` 指向那个 dylib。
内核侧代码签名/AMFI 会约束大致这类规则：来自文件的可执行映射，必须被有效代码签名覆盖。
不满足就会直接失败（`MAP_FAILED`），所以这段 hook：匿名 RW → 只读映射 dylib 并拷贝 → 再 `mprotect` 成原来的 `prot`。

- hooked___fcntl

```c
static int hooked___fcntl(int fildes, int cmd, void *param) {
  if (cmd == F_ADDFILESIGS_RETURN) {
    orig_fcntl(fildes, cmd, param);
    fsignatures_t *fsig = (fsignatures_t *)param;
    fsig->fs_file_start = 0xFFFFFFFF;
    return 0;
  }
  // Signature sanity check by dyld
  else if (cmd == F_CHECK_LV) {
    orig_fcntl(fildes, cmd, param);
    return 0;
  }

```

忽略“Catalyst/模拟器”下的情况：
- `F_ADDFILESIGS_RETURN`：先走原 `fcntl`（尝试挂签名），再改结构体里返回的 offset 相关字段（`fs_file_start = 0xFFFFFFFF`），并 `return 0`，让调用方以为挂签成功且范围足够。
- `F_CHECK_LV`：仍可调用原 `fcntl`，但无论结果如何都 `return 0`，即告诉 dyld「LV 允许映射」。

## Hook 过程可视化

一次实机测试：`dyld=0x1ce0c9000`，mmap 钩点 `+0x2cd84`，fcntl 钩点 `+0x2e124`。

```text
                    dyld @ 0x1ce0c9000
                           │
              mmap stub ───┴── 0x1ce0f5d84 (+0x2cd84)

  ┌─────────────── BEFORE ────────────────┐    ┌────────────── AFTER ──────────────────┐
  │ 0x…5d84  mov x16, #0xc5   (mmap)      │    │ 0x…5d84  ldr x8, #16                  │
  │ 0x…5d88  svc #0x80                    │    │ 0x…5d88  br  x8                       │
  │ 0x…5d8c  b.lo                         │ => │ 0x…5d8c  nop                          │
  │ 0x…5d90  pacibsp                      │    │ 0x…5d90  nop                          │
  │ 0x…5d94  ...                          │    │ 0x…5d94  .quad 0x104644d80  ──────────┼──► hooked_mmap
  └───────────────────────────────────────┘    └───────────────────────────────────────┘

              fcntl stub ──── 0x1ce0f7124 (+0x2e124)

  ┌─────────────── BEFORE ────────────────┐    ┌────────────── AFTER ──────────────────┐
  │ 0x…7124  mov x16, #0x5c   (fcntl)     │    │ 0x…7124  ldr x8, #16                  │
  │ 0x…7128  svc #0x80                    │    │ 0x…7128  br  x8                       │
  │ 0x…712c  b.lo                         │ => │ 0x…712c  nop                          │
  │ 0x…7130  pacibsp                      │    │ 0x…7130  nop                          │
  │ 0x…7134  ...                          │    │ 0x…7134  .quad 0x104644f10 ───────────┼──► hooked___fcntl
  └───────────────────────────────────────┘    └───────────────────────────────────────┘
```

## Reference
- [lv_bypass.c](https://github.com/khanhduytran0/coruna/blob/duy/decompile/TweakLoader/lv_bypass.c)
