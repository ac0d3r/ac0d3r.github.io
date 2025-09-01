# 学习课程
> [南京大学（李樾、谭添老师）的课程《软件分析》](https://tai-e.pascal-lab.net/lectures.html)

各类笔记：
- [Static Program Analysis Book](https://ranger-nju.gitbook.io/static-program-analysis-book)
- [静态分析入门](https://fushuling.com/index.php/2025/01/08/%e9%9d%99%e6%80%81%e5%88%86%e6%9e%90%e5%85%a5%e9%97%a8/)
- [geekby - 静态程序分析](https://www.geekby.site/2022/02/%E9%9D%99%E6%80%81%E7%A8%8B%E5%BA%8F%E5%88%86%E6%9E%90%E7%B3%BB%E5%88%97%E4%B8%80/)

# 编译与静态分析的关系

<img src="https://github.com/user-attachments/assets/f15f4537-1145-48ef-b4c3-ecf7b61e572b" height="350">

在 [Introduction to the Go compiler](https://go.dev/src/cmd/compile/README) 也能看到相似的流程，静态分析主要发生在IR层，生成机器码后端部分(back-end)那就是编译器所考虑的了。

- 词法分析器（Scanner）结合正则表达式(Regular Expression) ，通过词法分析（Lexical Analysis）将源码翻译为 token。
- 语法分析器（Parser）根据上下文无关文法（Context-Free Grammar）通过语法分析（Syntax Analysis），将 tokens 解析为抽象语法树（Abstract Syntax Tree, AST）
- 语义分析器（Type Checker），结合属性文法（Attribute Grammar），通过语义分析（Semantic Analysis），将 AST 解析为 decorated AST
- Translator 将 decorated AST 翻译为中间表示形式（Intermediate Representation, IR）通常是三地址码会(Three address code, 3AC)，并基于 IR 做静态分析。
- Code Generator，将 IR 转换为机器代码。

# 了解Go内部实现

## Scanner

Go的token定义在[token.go](https://github.com/golang/go/blob/master/src/go/token/token.go)文件，还包含对[标识符](https://github.com/golang/go/blob/master/src/go/token/token.go#L331-L341)，[关键词](https://github.com/golang/go/blob/master/src/go/token/token.go#L322-L326)等判断。

[Scan](https://github.com/golang/go/blob/master/src/go/scanner/scanner.go#L80-L974) 方法实现词法分析将源码翻译为tokens。

<img src="https://github.com/user-attachments/assets/607207d4-df06-46f4-9714-168e635cd3e3" height="250">

## Parser

获得tokens流后通过文法（Grammar）将其处理为AST(Abstract Syntax Tree，抽象语法树)，[Go 编程语言规范](https://go.dev/ref/spec) 有关于文法说明：

```Prolog
SourceFile = PackageClause ";" { ImportDecl ";" } { TopLevelDecl ";" } .
PackageClause = "package" PackageName .
PackageName   = identifier .

ImportDecl = "import" ( ImportSpec | "(" { ImportSpec ";" } ")" ) .
ImportSpec = [ "." | PackageName ] ImportPath .
ImportPath = string_lit .

Declaration  = ConstDecl | TypeDecl | VarDecl .
TopLevelDecl = Declaration | FunctionDecl | MethodDecl .
```

每个 Go 源代码文件最终都会被解析成一个独立的抽象语法树，所以语法树最顶层的结构或者开始符号都是 SourceFile。
每一个文件都包含一个 package 的定义以及可选的 import 声明和其他的顶层声明，顶层声明包括：常量，类型，别名，变量，函数等。

除此之外，[Go 编程语言规范](https://go.dev/ref/spec) 还包含了 Types,Blocks,Declarations,Expressions,Statements 等文法。

---

[go/ast](https://github.com/golang/go/blob/master/src/go/ast/ast.go#L32-L54) 中定义`Node`,`Expr`,`Stmt`,`Decl`几个接口，其中表达式(expression),语句(statement)和声明(declaration)是语法的三个主体，Node是基类接口任何类型的主体都是Node，用于标记该节点位置的开始和结束。

使用 `go/parser` 来解析下代码看看AST的结构：

```go
...
import (
	"go/ast"
	"go/parser"
	"go/token"
)

func TestParser() {
	fs := token.NewFileSet()
	src := `package foo

import (
	"fmt"
	"time"
)

var a string

func foo() {
	if a != "" {
		fmt.Println(a)
	}

	for i:=0; i<10; i++{
		fmt.Println(i)
	}

	fmt.Println(time.Now())
}
`
	fast, _ := parser.ParseFile(fs, "foo.go", src, parser.ParseComments)
	ast.Print(fs, fast)
}
```

除了可以用 `ast.Print` 打印语法树，还可以使用可视化工具[goast-viewer](https://yuroyoro.github.io/goast-viewer/)：

<img src="https://github.com/user-attachments/assets/c1fa6d56-fd96-49f3-b26e-3bde5f14226c" height="350">

Go文件的AST结构大致如图(参考[《Go 语言设计与实现》](https://draven.co/golang/docs/part1-prerequisite/ch02-compile/golang-compile-intro/))：

<img src="https://github.com/user-attachments/assets/73cb0347-1ea2-415f-9257-27a6ae0fc9e6" height="350">

## IR

IR 是编译器或静态分析工具将源代码转换为一种便于分析和优化的中间形式，通常是与源语言和目标平台无关的表示。它保留了程序的语义，方便后续分析、优化和代码生成。

IR 可以是多种形式，如AST（抽象语法树）、三地址码、图、或字节码。

**IR的分类：**

- 树IR：AST(Abstract Syntax Tree)
- 线性IR：3AC(Three Address Code)
- 图IR：CFG(Control Flow Graph), SSA(Static Single Assignment Form), PDG(Program Dependence Graph) ...

**静态分析为什么使用IR而非AST呢？**

AST 是一个语法树的形式，是一个高层级的形式，更加接近程序的源代码，语言相关的，适合做快速的类型检测，但是缺少了**控制流**、**数据流**的信息。

<img src="https://github.com/user-attachments/assets/3313e50c-e326-4796-bfbe-4d4d6ae14303" height="250">

- AST 是 high-level 且接近语法结构的，而 IR 是 low-level 且接近机器代码的。
- AST 是依赖于语言的，IR 通常是独立于语言的：三地址码会被分析器重点关注，因为可以将各种前端语言统一翻译成同一种 IR 再加以优化。
- AST 适合快速类型检查，IR 的结构更加紧凑和统一：在 AST 中包含了很多非终结符所占用的结点（body, assign 等），而 IR 中不会需要到这些信息。
- AST 缺少控制流信息，IR 包含了控制流信息：AST 中只是有结点表明了这是一个 do-while 结构，但是无法看出控制流信息；而 IR 中的 goto 等信息可以轻易看出控制流。

因此 IR 更适合作为静态分析的基础。

### GoSSA

Go的编译器在中间表示（IR）中使用 SSA（静态单赋值，Static Single Assignment） 形式。

这个图从左到右分别是：AST,CFG,SSA，SSA 是基于 CFG 的一种：

<img src="https://github.com/user-attachments/assets/f866a311-5889-43e3-a8d7-c99cb00a0c31" height="250">

CFG 是一个过程或程序的抽象表现，是用在编译器中的一个抽象数据结构，由编译器在内部维护，代表了一个程序执行过程中会遍历到的所有路径。它用图的形式表示一个过程内所有基本块执行的可能流向, 也能反映一个过程的实时执行过程。

- CFG 的节点是基本块（Basic Blocks），表示一组顺序执行的语句；边表示控制流跳转（如 if 分支、循环、或 goto）。
- 将函数的语句组织成基本块（Basic Blocks），每个基本块是一组顺序执行的指令，没有中间的跳转或分支。


在 [Go Tools](https://cs.opensource.google/go/x/tools) 仓库其中包含各种工具和包，主要用于 Go 程序的静态分析。`go/cfg` 为 Go 函数提供将AST生成为一个简单的控制流图：

```go
...
fs := token.NewFileSet()
src := `package foo

func max(a, b int) int {
    if a > b {
        return a
    }
    return b
}
`
fast, _ := parser.ParseFile(fs, "foo.go", src, parser.ParseComments)
// find max func decl
var funcDecl *ast.FuncDecl
for _, decl := range fast.Decls {
	if f, ok := decl.(*ast.FuncDecl); ok && f.Name.Name == "max" {
		funcDecl = f
		break
	}
}
// build cfg with ast
cfg := cfg.New(funcDecl.Body, func(expr *ast.CallExpr) bool { return false })
// generate cfg dot
cfg.Dot(fs)
```

使用[GraphvizOnline](https://dreampuf.github.io/GraphvizOnline)展示CFG(without Unreachable node)：

<img src="https://github.com/user-attachments/assets/a275bf3a-4e39-4956-ae63-a5c9b8f5949f" height="250">

---

SSA是基于CFG的中间表示（IR），所以基本块直接对应 CFG 的基本块，控制流边（block.Succs）保持不变。但每个变量只赋值一次，ssa会为每个变量的每次赋值生成唯一版本（例如，x1、x2）。跟踪每个基本块中的变量定义（Def）和使用（Use）。在控制流合并点（例如，if 分支合并），插入 `φ(phi)` 函数选择变量值，使用支配树（Dominator Tree）确定 `φ` 函数的插入位置。

Phi 指令（来源于希腊字母 φ）是 SSA 的核心特性，用于处理变量在不同控制流路径上的不同赋值。它的作用是在控制流合并点根据到达当前块的前驱块选择正确的变量值。简单来说，Phi 就像一个“选择器”，它根据程序执行的路径动态决定变量的值。

go 编译工具有个`GOSSAFUNC`参数可以指定生成某个函数SSA，以下代码为例：

```go
package main

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func main() {
	println(max(1, 2))
}
```

使用 `$GOSSAFUNC=max go build foo.go` 会生成 ssa.html 文件在浏览器上打开：

<img src="https://github.com/user-attachments/assets/bf35a201-4a6e-4c90-af42-15534b428e38" height="260">

可以看到 `If v6 → b3 b2 (5)` v6即`b`为 true 时跳转到 b3, false 跳转到 b2。(Tip: `(5)`表示源码第五行 )

<img src="https://github.com/user-attachments/assets/7bcfe44b-51f5-4dcc-823e-00738b555f52" height="250">

现在假设 `b` 为true，跳转到 b3 块后 `Plain → b2 (8)` 指无条件跳转b2，b2 块中 `v10 (8) = Phi <int> v8 v9 (x[int])` v10 的值就是 return 的值，`Phi` 函数需要根据控制流选择 v8 或 v9。如从`b3`跳转过来的就选v9 即为`8`。

但是 `phi` 具体怎么实现也不知道，后面还有一堆优化，不去研究下编译器后端的话是看不懂一点。

接下来想通过分析现有工具了解一下如何实现 Go 静态分析。

# gosec
> [gosec](https://github.com/securego/gosec) 是一个Go安全检查工具，它通过分析Go代码的AST和SSA表示来检测安全问题。
 
gosec 规则如下：

- 基于 AST 检测的
```
G101: Look for hardcoded credentials
G102: Bind to all interfaces
G103: Audit the use of unsafe block
G104: Audit errors not checked
G106: Audit the use of ssh.InsecureIgnoreHostKey function
G107: Url provided to HTTP request as taint input
G108: Profiling endpoint is automatically exposed
G109: Converting strconv.Atoi result to int32/int16
G110: Detect io.Copy instead of io.CopyN when decompression
G111: Detect http.Dir('/') as a potential risk
G112: Detect ReadHeaderTimeout not configured as a potential risk
G114: Use of net/http serve function that has no support for setting timeouts
G201: SQL query construction using format string
G202: SQL query construction using string concatenation
G203: Use of unescaped data in HTML templates
G204: Audit use of command execution
G301: Poor file permissions used when creating a directory
G302: Poor file permissions used when creation file or using chmod
G303: Creating tempfile using a predictable path
G304: File path provided as taint input
G305: File path traversal when extracting zip archive
G306: Poor file permissions used when writing to a file
G307: Poor file permissions used when creating a file with os.Create
G401: Detect the usage of MD5 or SHA1
G402: Look for bad TLS connection settings
G403: Ensure minimum RSA key length of 2048 bits
G404: Insecure random number source (rand)
G405: Detect the usage of DES or RC4
G406: Detect the usage of deprecated MD4 or RIPEMD160
G501: Import blocklist: crypto/md5
G502: Import blocklist: crypto/des
G503: Import blocklist: crypto/rc4
G504: Import blocklist: net/http/cgi
G505: Import blocklist: crypto/sha1
G506: Import blocklist: golang.org/x/crypto/md4
G507: Import blocklist: golang.org/x/crypto/ripemd160
G601: Implicit memory aliasing in RangeStmt
```
- 基于SSA检测：

```
G115: Type conversion which leads to integer overflow
G407: Use of hardcoded IV/nonce for encryption
G602: Possible slice bounds out of range
```

我们以 `G101(Look for hardcoded credentials)` 规则为例，gosec 是如何使用 AST 进行检测的：

- ast 规则定义
```go
func Generate(trackSuppressions bool, filters ...RuleFilter) RuleList {
	rules := []RuleDefinition{
		{"G101", "Look for hardcoded credentials", NewHardcodedCredentials},
		...
	}
}
```

- 规则初始化。返回[]ast.Node表示rule对应哪些节点，比如这里是对应：赋值语句（=, :=, += 等）、变(常)量声明、二元表达式

```go
func NewHardcodedCredentials(id string, conf gosec.Config) (gosec.Rule, []ast.Node) {
	pattern := `(?i)passwd|pass|password|pwd|secret|token|pw|apiKey|bearer|cred`
	return &credentials{
		pattern:          regexp.MustCompile(pattern),
		...
		MetaData: issue.MetaData{
			ID:         id,
			What:       "Potential hardcoded credentials",
			Confidence: issue.Low,
			Severity:   issue.High,
		},
	}, []ast.Node{(*ast.AssignStmt)(nil), (*ast.ValueSpec)(nil), (*ast.BinaryExpr)(nil)}
}
```

- analyzer 初始化，规则注册

```go
analyzer := gosec.NewAnalyzer(config, *flagScanTests, *flagExcludeGenerated, *flagTrackSuppressions, *flagConcurrency, logger)
analyzer.LoadRules(ruleList.RulesInfo()) 
```

- 按照 ast.Node 类型分类注册

```go
func (r RuleSet) Register(rule Rule, isSuppressed bool, nodes ...ast.Node) {
	for _, n := range nodes {
		t := reflect.TypeOf(n)
		if rules, ok := r.Rules[t]; ok {
			r.Rules[t] = append(rules, rule)
		} else {
			r.Rules[t] = []Rule{rule}
		}
	}
	...
}
```

- analyzer使用 "golang.org/x/tools/go/packages" 模块加载Go源码，用于加载和解析 Go 包的元数据，包括源代码的 AST（抽象语法树）、类型信息和其他相关信息。

```go
pkgs, err := packages.Load(conf, packageFiles...)
```
- 遍历 package 下的文件AST，进行规则检测

```go
// gosec.CheckRules(pkg)

for _, file := range pkg.Syntax {
	...
	ast.Walk(gosec, file)
}
```
- gosec 实现了 ast.Visitor 接口

```go	
func (gosec *Analyzer) Visit(n ast.Node) ast.Visitor {
	...
	// 获取 ast.node 注册的对应规则
	for _, rule := range gosec.ruleset.RegisteredFor(n) {
		issue, err := rule.Match(n, gosec.context)
		...
		gosec.updateIssues(issue)
	}
	return gosec
}
```

- 这里调用规则的 Match 函数, 仍然以 hardcoded credentials 为例：
  - matchAssign 先判断左边表达式是否为 ast.Ident 是否能匹配 `(?i)passwd|pass|password|pwd|secret|token|pw|apiKey|bearer|cred` 或者判断右边（如是string）是否满足 secretsPatterns 的规则
  - matchValueSpec 也是差不多，分别对  valueSpec.Names valueSpec.Values 进行匹配
  - matchEqualityCheck 当 Op 符号为 "==" "!=" 尝试匹配 binaryExpr.X,Y node。

```go
func (r *credentials) Match(n ast.Node, ctx *gosec.Context) (*issue.Issue, error) {
	switch node := n.(type) {
	case *ast.AssignStmt:
		return r.matchAssign(node, ctx)
	case *ast.ValueSpec:
		return r.matchValueSpec(node, ctx)
	case *ast.BinaryExpr:
		return r.matchEqualityCheck(node, ctx)
	}
	return nil, nil
}
```

大概了解AST检测机制后，再通过`G602: Possible slice bounds out of range` 规则为例，gosec 是如何使用 SSA 进行检测的：

- SSA规则定义

```go
var defaultAnalyzers = []AnalyzerDefinition{
	{"G115", "Type conversion which leads to integer overflow", newConversionOverflowAnalyzer},
	...
}
```

- SSA规则注册

```go
// analyzer.LoadAnalyzers(analyzerList.AnalyzersInfo())
...
for id, def := range analyzerDefinitions {
	r := def.Create(def.ID, def.Description)
	gosec.analyzerSet.Register(r, analyzerSuppressed[id])
}
// Register 函数
func (a *AnalyzerSet) Register(analyzer *analysis.Analyzer, isSuppressed bool) {
	a.Analyzers = append(a.Analyzers, analyzer)
	...
}
```

- 规则检测

```go
// gosec.CheckAnalyzers(pkg)
...
ssaResult, err := gosec.buildSSA(pkg) // // 将 pkg 转换为 ssa
// 准备result
resultMap := map[*analysis.Analyzer]interface{}{
	buildssa.Analyzer: &analyzers.SSAAnalyzerResult{
		Config: gosec.Config(),
		Logger: gosec.logger,
		SSA:    ssaResult.(*buildssa.SSA),
	},
}
// 依次运行注册的 Analyzer
for _, analyzer := range gosec.analyzerSet.Analyzers {
	pass := &analysis.Pass{
		Analyzer:          analyzer,
		Fset:              pkg.Fset,
		Files:             pkg.Syntax,
		OtherFiles:        pkg.OtherFiles,
		IgnoredFiles:      pkg.IgnoredFiles,
		Pkg:               pkg.Types,
		TypesInfo:         pkg.TypesInfo,
		TypesSizes:        pkg.TypesSizes,
		ResultOf:          resultMap,
		...
	}
	result, err := pass.Analyzer.Run(pass)
	...
}
```

-  slice bounds 具体实现逻辑

```go
func newSliceBoundsAnalyzer(id string, description string) *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:     id,
		Doc:      description,
		Run:      runSliceBounds,
		Requires: []*analysis.Analyzer{buildssa.Analyzer},
	}
}

func runSliceBounds(pass *analysis.Pass) (interface{}, error) {
	ssaResult, err := getSSAResult(pass)
	...
	// 对每个函数（SrcFuncs）和基本块（DomPreorder）进行分析。
	for _, mcall := range ssaResult.SSA.SrcFuncs {
		for _, block := range mcall.DomPreorder() {
			for _, instr := range block.Instrs {
				// 处理 *ssa.Alloc（slice 分配）
				instr.(*ssa.Alloc)
				// 提取容量大小
				sliceCap, err := extractSliceCapFromAlloc(instr.String())
				// 查找引用
				allocRefs := instr.Referrers()
				for _, instr := range *allocRefs {
					slice, ok := instr.(*ssa.Slice) // 确保是切片操作
					...
					l, h := extractSliceBounds(slice) // 获取切片的上下界（low, high）
					newCap := computeSliceNewCap(l, h, sliceCap) // 根据切片边界和原始容量重新计算新 slice 的容量
					violations := []ssa.Instruction{}
					trackSliceBounds(0, newCap, slice, &violations, ifs)// 递归检查该 slice 的后续使用，记录越界操作
					// 包括切片操作、索引访问、函数调用、if判断长度等。
				}
			}
		}
	}
	// 判断if操作，消除误报
	for ifref, binop := range ifs {
		bound, value, err := extractBinOpBound(binop) // 提取边界信息（bound 和 value）
		for i, block := range ifref.Block().Succs { // 分析if 语句所在基本块的后继块
			if i == 1 { //（0 表示真分支，1 表示假分支）
				bound = invBound(bound) // 反转bound的值
			}
			var processBlock func(block *ssa.BasicBlock, depth int)
			...
			// processBlock会遍历基本块中的指令（block.Instrs）
			// 根据 bound 的类型（lowerUnbounded、upperUnbounded、unbounded、upperBounded）执行不同的逻辑：
			// 1. 消除误报（从 issues 中移除）。
			// 2. 分析切片操作（ssa.Slice）或索引操作（ssa.IndexAddr）是否在边界内。
			// 如果遇到嵌套的 if 语句（ssa.If），递归分析其后继块。使用depth 参数控制递归深度，防止无限递归。
		}
}
```

## gosec 的缺点

总结一下，gosec 主要通过分析 Go 的抽象语法树（AST）进行检查，部分规则利用了 go/ssa 进行简单的控制流和数据流分析。不支持全局（global）数据流分析，遇到复杂的跨函数/模块跟踪等力较弱，好在轻量，适合快速扫描。

# 更更更强的工具

一个好用SAST分析工具，得有个强大的污点分析引擎、支持本地和全局数据流分析和支持多语言的。

## Joern
> https://github.com/joernio/joern

Joern 是一个开源代码分析平台，专注于 C/C++、Java 等语言，通过生成代码属性图（CPG）进行静态分析，支持 Scala 的查询语言。

<img src="https://github.com/user-attachments/assets/275d0080-fff8-4768-beec-602829763230" height="350">

## CodeQL
> https://codeql.github.com/docs/

基于数据流图（data flow graph），支持本地和全局数据流分析，精确跟踪跨函数/模块的污点传播。QL 查询可定义源、汇和 sanitization 规则。

**CodeQL zero to hero**

- [CodeQL zero to hero part 1: The fundamentals of static analysis for vulnerability research](https://github.blog/developer-skills/github/codeql-zero-to-hero-part-1-the-fundamentals-of-static-analysis-for-vulnerability-research/)
- [CodeQL zero to hero part 2: Getting started with CodeQL](https://github.blog/developer-skills/github/codeql-zero-to-hero-part-2-getting-started-with-codeql/)
- [CodeQL zero to hero part 3: Security research with CodeQL](https://github.blog/security/vulnerability-research/codeql-zero-to-hero-part-3-security-research-with-codeql/)

**Go 相关**

- https://codeql.github.com/docs/codeql-language-guides/codeql-library-for-go/

# 参考链接
- [Go 语言设计与实现](https://draven.co/golang/docs/part1-prerequisite/ch02-compile/golang-compile-intro/)
- [Unveiling the Power of Intermediate Representations for Static Analysis: A Survey](https://arxiv.org/abs/2405.12841)
- [深入理解 LLVM 代码生成](https://www.bilibili.com/video/BV1GCo4YmEK6/)
- [Why your code is a Graph](https://blog.shiftleft.io/why-your-code-is-a-graph-f7b980eab740)
- [lorexxar - sast2024](https://lorexxar.cn/2023/12/18/sast2024/)

# 结语

本文内容如有错误或疏漏之处，欢迎读者朋友指出或与我交流讨论，您的宝贵意见将帮助我不断改进！