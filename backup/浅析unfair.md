现在自动砸壳基本用这个方案：ipatool(ApplePackage) + unfair(d)；
ipatool 负责下载 ipa；unfair 负责解密。

unfair 一开始只支持 macOS ≤11.2.3（Apple Silicon），底层调用 mremap_encrypted；之后版本 FairPlay 检测严格无法再成功解密。
之后 [lbr77/unfair](https://github.com/lbr77/unfair) 支持了 Jailbroken iOS。

## unfair on Jailbroken iOS

`unfair package` 的执行路径：把自己提成 platform binary -> 把 App 伪装成已安装布局 -> 用 `mremap_encrypted` 让内核 FairPlay pager 解出明文 -> 写回 IPA 并剥掉 `SC_Info`。

**准备环境**

- 以 **root** 运行
- 加载 `libjailbreak`，给当前进程打上 `CS_PLATFORM_BINARY`；否则后续 `mremap_encrypted / FairPlay` 解密会失败（权限不足）。

```c
// 86:137:Sources/UnfairSupport/UnfairSupport.c
int unfair_prepare_app_bundle_decryption(char *error, size_t error_size) {
#if defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE
    static int prepared = 0;
    if (prepared) {
        return 0;
    }

    if (geteuid() != 0) {
        set_error(error, error_size, "root privileges required for jailbreak primitives");
        return -1;
    }

    void *handle = open_libjailbreak(error, error_size);
    // ...
    if (jbclient_initialize_primitives() != 0) {
        set_error(error, error_size, "jbclient_initialize_primitives failed");
        return -1;
    }

    uint64_t proc = proc_find(getpid());
    // ...
    int status = proc_csflags_set(proc, UNFAIR_CS_PLATFORM_BINARY);
    proc_rele(proc);
    // ...
    prepared = 1;
    return 0;
```

---

1. **解压 IPA**

- 先 `extractIPA` 解到临时工作目录
- `scanBinaries` 扫描带 `LC_ENCRYPTION_INFO_64` 且 `cryptid==1` 的 Mach-O，只 stage 这些加密二进制文件

```swift
// 50:60:Sources/UnfairKit/PackageProcessor.swift
private func processStagedPackage(input: URL, output: URL, workingDirectory: URL, payloadURL: URL) throws {
    let sourceApps = try appBundles(in: payloadURL)
    guard sourceApps.count == 1, let sourceApp = sourceApps.first else {
        throw UnfairError.io("iOS package mode expects one Payload/*.app bundle")
    }

    try UnfairProcessPermissions.prepareForAppBundleDecryption(logger: logger)
    let sourceRecords = try MachOInspector.scanBinaries(appURL: sourceApp, label: sourceApp.lastPathComponent)
    let encryptedRecords = sourceRecords.filter(\.isEncrypted)
    let stagedApp = try AppBundleStager.stageAppBundle(sourceApp: sourceApp, encryptedRecords: encryptedRecords, logger: logger)
    defer { AppBundleStager.cleanup(stagedApp) }
    ...
```

2. **Stage（伪装成已安装 App）**

FairPlay 建解密会话时会看映射文件的真实路径（以及 `SC_Info`）。
系统安装的 App 落在 `/var/containers/Bundle/Application/<UUID>/*.app/`，并归 `_installd` 所有；

- 在 `Application` 根下建 UUID 容器 + `.app`

```swift
// 79:91:Sources/UnfairKit/AppBundleStager.swift
private static func createBundle(appName: String, logger: UnfairLogger) throws -> StagedAppBundle {
    let container = applicationBundleRoot.appendingPathComponent(UUID().uuidString, isDirectory: true)
    let app = container.appendingPathComponent(appName, isDirectory: true)
    try createStagingDirectory(container)
    // ...
    return StagedAppBundle(containerURL: container, appURL: app)
}
```

- 拷贝加密二进制及其旁路 `SC_Info`（含 `.sinf` 等）

```swift
// 51:72:Sources/UnfairKit/AppBundleStager.swift
static func stageAppBundle(sourceApp: URL, encryptedRecords: [MachORecord], logger: UnfairLogger) throws -> StagedAppBundle {
    let bundle = try createBundle(appName: sourceApp.lastPathComponent, logger: logger)
    let sourceSCInfo = sourceApp.appendingPathComponent("SC_Info", isDirectory: true)
    _ = try copyCredentials(from: sourceSCInfo, explicitRootSinf: nil, binaryName: nil, to: bundle.appURL)

    for record in encryptedRecords {
        let relativePath = try relativePath(of: record.url, in: sourceApp)
        let destination = bundle.appURL.appendingPathComponent(relativePath)
        try copyFile(record.url, to: destination)
        let sourceSCInfo = record.url.deletingLastPathComponent().appendingPathComponent("SC_Info", isDirectory: true)
        _ = try copyCredentials(
            from: sourceSCInfo,
            explicitRootSinf: nil,
            binaryName: record.name,
            to: destination.deletingLastPathComponent()
        )
        try FileSystem.chmod(destination, mode: 0o755)
    }
    try applyInstalledAppOwnership(to: bundle.containerURL) 
    // ...
    return bundle
}
```

- 整棵目录 `chown` 给 `_installd`

```swift
private static func applyInstalledAppOwnership(to url: URL) throws {
    guard let user = getpwnam("_installd"), let group = getgrnam("_installd") else {
        throw UnfairError.io("_installd user/group missing")
    }
    try chownRecursively(url, uid: user.pointee.pw_uid, gid: group.pointee.gr_gid)
}
```

3. **逐个解密二进制**

- 主循环：
  - validateDecryptableLocation(staged / output)
  - cwd = staged 目录
  - decryptBinary(stagedAt:outputURL:rootSinf:)
    - installTemporarySinf / removeTemporarySinf
    - open staged RO + output RW
    - mapWritableBinary(output) → inspectMappedBinary # 读 cryptoff/cryptsize
    - withPreparedDecryption → unprotectRegion
        - 按块 decryptChunk: mmap(staged) → mremap_encrypted(cryptid=2) → memcpy(output) → munmap
    - markDecrypted # LC_ENCRYPTION_INFO_64.cryptid 改成 0
    - msync(output)

```swift
// 94:112:Sources/UnfairKit/PackageProcessor.swift
for stagedRecord in encryptedStagedRecords {
    guard let outputRecord = outputsByDisplayPath[stagedRecord.displayPath] else {
        throw UnfairError.io("output binary missing: \(stagedRecord.displayPath)")
    }
    let binaryDir = stagedRecord.url.deletingLastPathComponent()
    try validateDecryptableLocation(stagedRecord.url, label: "staged binary")
    try validateDecryptableLocation(outputRecord.url, label: "output binary")
    ...
    FileManager.default.changeCurrentDirectoryPath(binaryDir.path) // cwd
    try decryptor.decryptBinary(
        stagedAt: URL(fileURLWithPath: stagedRecord.name),
        outputURL: outputRecord.url,
        rootSinf: rootSinf,
        displayPath: stagedRecord.displayPath
    )
    decryptedOutputRecords.append(outputRecord)
}
try verifyDecryptedBinaries(in: outputApp, label: label)
```

拷贝 `.sinf`：

```swift
// 108:112:Sources/UnfairKit/BinaryDecryptor.swift
public func decryptBinary(stagedAt stagedURL: URL, outputURL: URL, rootSinf: URL, displayPath: String? = nil) throws {
    let temporarySinf = try installTemporarySinf(for: stagedURL, rootSinf: rootSinf)
    defer { removeTemporarySinf(temporarySinf) }
    let status = try decryptBinary(stagedAt: stagedURL, outputURL: outputURL)
    // ...
}
```

读 staged、写 Payload：

```swift
// 202:250:Sources/UnfairKit/BinaryDecryptor.swift
private func decryptBinary(stagedAt stagedURL: URL, outputURL: URL) throws -> DecryptionStatus {
    let stagedFD = open(stagedURL.path, O_RDONLY)
    let outputFD = open(outputURL.path, O_RDWR)
    ...
    let mappedOutput = try mapWritableBinary(fd: outputFD)  // mmap 的是 output
    let output = try inspectMappedBinary(mappedOutput.base, fileSize: mappedOutput.size)
    // ...
    try withPreparedDecryption {
        try unprotectRegion(
            fd: stagedFD,                          // 解密映射来自 staged
            fileOffset: output.slice.offset,
            destinationSliceBase: output.sliceBase, // 明文写入 output
            info: enc
        )
    }
    try markDecrypted(sliceBase: output.sliceBase, commandOffset: enc.commandOffset)
    guard msync(mappedOutput.base, mappedOutput.size, MS_SYNC) == 0 else { /* ... */ }
    return .decrypted
}
```

核心(单块流程)：`mmap` + `remap(mremap_encrypted)` + `memcpy` + 最后 `unmap`

```swift
// 372:403:Sources/UnfairKit/BinaryDecryptor.swift
func decryptChunk(fd: Int32, chunk: EncryptedRegionChunk, destinationSliceBase: UnsafeMutableRawPointer) throws {
    // 1) mmap staged 上这一块加密区（PROT_READ / MAP_PRIVATE）
    guard let mapping = encryptedRegionSystemCalls.map(
        nil, chunk.size, PROT_READ, MAP_PRIVATE, fd, off_t(chunk.fileOffset)
    ) else { /* ... */ }
    defer { _ = encryptedRegionSystemCalls.unmap(mapping, chunk.size) }  // 4) munmap

    // 2) mremap_encrypted：内核把 mapping 换成明文页（cryptid 参数用 model=2）
    let result = try encryptedRegionSystemCalls.remap(
        mapping, chunk.size,
        Self.modelEncryptionCryptid,  // 2
        cpuTypeArm64, cpuSubtypeArm64All
    )
    guard result == 0 else { /* ... */ }

    // 3) 明文拷进 output 映射
    memcpy(destinationSliceBase.advanced(by: chunk.destinationOffset), mapping, chunk.size)
}
```

4. **收尾**

- `AppBundleStager.cleanup` 删 staging
- `PackageArchiveWriter` 重打包：替换已解密二进制；`ArchivePrivacyFilter` 去掉 `Payload/.../SC_Info/**`
- `verifyDecryptedBinaries` 确认无残留 `cryptid == 1`


## Reference

- https://github.com/lbr77/unfair