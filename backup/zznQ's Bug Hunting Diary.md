> zznQの捉虫日记
  我并不是一名专业的漏洞挖掘研究员，偶尔会对生活和工作接触到或感兴趣的软件进行简单研究。
  这里会记录下我捉虫的思路，大多数会很水，但希望能越捉越好。
  我主要分为了三类：BUG(算不上漏洞的)、Vulnerability、Tool(挖掘工具的研究)。

# BUG

<details>
<summary>A memory error bug caused by race conditions in multithreaded use of curl_cffi</summary>

在试用 [grok2api_python](https://github.com/xLmiler/grok2api_python) 时会多次出现这个错误：

![](https://github.com/user-attachments/assets/a791dfa1-3bcc-4673-9bb2-4da62fd39310)

我看了下依赖库，首先定位到curl_cffi。它通过访问低级C接口操作堆栈，这里可能会存在问题。打印完整的堆栈信息：
```
python(32059,0x31402b000) malloc: Corruption of tiny freelist 0x1048d6cb0: size too small (1/57)
python(32059,0x31402b000) malloc: *** set a breakpoint in malloc_error_break to debug
Fatal Python error: Aborted

Thread 0x00000003341ab000 (most recent call first):
  File "../grok2api_python/.venv/lib/python3.12/site-packages/curl_cffi/curl.py", line 362 in perform
  File "../grok2api_python/.venv/lib/python3.12/site-packages/curl_cffi/requests/session.py", line 593 in perform
  ...
```

进一步分析发现，问题的根因是在多线程并发情况下使用 curl_cffi 的 [streaming](https://curl-cffi.readthedocs.io/en/latest/quick_start.html#streaming-response) 功能时，存在条件竞争，导致内存错误。

</details>

<details>
    <summary>Directory Traversal in sing-box-for-apple iCloud Path Parameter</summary>

- 仓库不支持提issue，就直接提PR: https://github.com/SagerNet/sing-box-for-apple/pull/9

singbox 是支持通过 urlscheme 去创建配置文件的，就想审计这部分能不能目录穿越，跟踪到[NewProfileView.createProfileBackground](https://github.com/SagerNet/sing-box-for-apple/blob/main/ApplicationLibrary/Views/Profile/NewProfileView.swift#L171C30-L171C53) 函数 `let profileConfig = profileConfigDirectory.appendingPathComponent("config_\(nextProfileID).json")` 文件名被改写后就不存在漏洞了。

创建 iCloud 类型配置时，path 参数存在目录穿越BUG：[code](https://github.com/SagerNet/sing-box-for-apple/blob/main/ApplicationLibrary/Views/Profile/NewProfileView.swift#L205-L210)

![](https://github.com/user-attachments/assets/3081e849-53c6-440e-bb89-6911ec7ea285)

singbox 开启了AppSandbox，既无法穿越到容器目录外，也不能远程调用，只能在本地创建，故只能算个水BUG。

</details>

<details>
<summary>Slice Out-of-Bounds Panic
 in beep(mp3.Decode)</summary>

- https://github.com/gopxl/beep/issues/209

通过 go fuzzing 发现的bug：

<img width="500" height="408" alt="Image" src="https://github.com/user-attachments/assets/e858fc10-3c23-4736-91a5-7c0dd0de4ad5" />

root cause 是它的上游依赖库：https://github.com/hajimehoshi/go-mp3 ，go-mp3 仓库已归档，即只能在报告在 beep 仓库。解决方法我想只能是用 `recover()` 去捕获panic。
</details>

# Vulnerability

# Tool
