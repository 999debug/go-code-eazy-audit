# go简单审计

此文档用于教学如何安装和使用`gosec`和`govulncheck`两款工具
快速检查源码是否存在危险函数和危险依赖

## 审计工具gosec使用

[项目](https://github.com/securego/gosec)
### 安装

安装命令：`go install github.com/securego/gosec/v2/cmd/gosec@latest`

正常来说安装完直接就可以用，但是在Windows上我的被安装到了`C:\Users\####\go\bin\windows_amd64`
需要配置一下环境变量

### 使用命令

`gosec -fmt=json -out=security-report.json ./... `
注意如果想确保扫描没问题，要先保障程序可以正常build，否则也会报错

扫描结果示例：
```json
{
	"Golang errors": {},
	"Issues": [
		{
			"severity": "HIGH",
			"confidence": "MEDIUM",
			"cwe": {
				"id": "338",
				"url": "https://cwe.mitre.org/data/definitions/338.html"
			},
			"rule_id": "G404",
			"details": "Use of weak random number generator (math/rand or math/rand/v2 instead of crypto/rand)",
			"file": "VNCTF2025\\GinTest_pulic\\utils\\jwt.go",
			"code": "17: \trand.Seed(config.Year())\n18: \trandomNumber := rand.Intn(1000)\n19: \tkey := fmt.Sprintf(\"%03d%s\", randomNumber, config.Key())\n",
			"line": "18",
			"column": "18",
			"nosec": false,
			"suppressions": null
		},
		{
			"severity": "MEDIUM",
			"confidence": "HIGH",
			"cwe": {
				"id": "78",
				"url": "https://cwe.mitre.org/data/definitions/78.html"
			},
			"rule_id": "G204",
			"details": "Subprocess launched with a potential tainted input or cmd arguments",
			"file": "VNCTF2025\\GinTest_pulic\\controllers\\controller.go",
			"code": "231: \n232: \tcmd := exec.Command(\"go\", \"run\", tmpFile.Name())\n233: \toutput, err := cmd.CombinedOutput()\n",
			"line": "232",
			"column": "9",
			"nosec": false,
			"suppressions": null
		},
		{
			"severity": "MEDIUM",
			"confidence": "HIGH",
			"cwe": {
				"id": "22",
				"url": "https://cwe.mitre.org/data/definitions/22.html"
			},
			"rule_id": "G304",
			"details": "Potential file inclusion via variable",
			"file": "VNCTF2025\\GinTest_pulic\\controllers\\controller.go",
			"code": "131: \tfilepath, _ := url.JoinPath(basepath, filename)\n132: \tout, _ := os.Create(filepath)\n133: \tdefer out.Close()\n",
			"line": "132",
			"column": "12",
			"nosec": false,
			"suppressions": null
		},
		{
			"severity": "LOW",
			"confidence": "HIGH",
			"cwe": {
				"id": "703",
				"url": "https://cwe.mitre.org/data/definitions/703.html"
			},
			"rule_id": "G104",
			"details": "Errors unhandled",
			"file": "VNCTF2025\\GinTest_pulic\\controllers\\controller.go",
			"code": "134: \tlog.Println(in)\n135: \tio.Copy(out, in)\n136: \tlog.Println(out)\n",
			"line": "135",
			"column": "2",
			"nosec": false,
			"suppressions": null
		},
		{
			"severity": "LOW",
			"confidence": "HIGH",
			"cwe": {
				"id": "703",
				"url": "https://cwe.mitre.org/data/definitions/703.html"
			},
			"rule_id": "G104",
			"details": "Errors unhandled",
			"file": "VNCTF2025\\GinTest_pulic\\controllers\\controller.go",
			"code": "128: \t}\n129: \tin.Seek(0, io.SeekStart)\n130: \tbasepath := \"./uploads\"\n",
			"line": "129",
			"column": "2",
			"nosec": false,
			"suppressions": null
		},
		{
			"severity": "LOW",
			"confidence": "HIGH",
			"cwe": {
				"id": "703",
				"url": "https://cwe.mitre.org/data/definitions/703.html"
			},
			"rule_id": "G104",
			"details": "Errors unhandled",
			"file": "VNCTF2025\\GinTest_pulic\\controllers\\controller.go",
			"code": "72: \tvar requestUser = model.User{}\n73: \tc.Bind(\u0026requestUser)\n74: \tusername := requestUser.Username\n",
			"line": "73",
			"column": "2",
			"nosec": false,
			"suppressions": null
		},
		{
			"severity": "LOW",
			"confidence": "HIGH",
			"cwe": {
				"id": "703",
				"url": "https://cwe.mitre.org/data/definitions/703.html"
			},
			"rule_id": "G104",
			"details": "Errors unhandled",
			"file": "VNCTF2025\\GinTest_pulic\\controllers\\controller.go",
			"code": "28: \tvar requestUser = model.User{}\n29: \tc.Bind(\u0026requestUser)\n30: \tusername := requestUser.Username\n",
			"line": "29",
			"column": "2",
			"nosec": false,
			"suppressions": null
		}
	],
	"Stats": {
		"files": 10,
		"lines": 510,
		"nosec": 0,
		"found": 7
	},
	"GosecVersion": "dev"
}
```

这道题目的官方题解利用的便是这个`"severity": "HIGH",`的问题点

这里有一个问题需要注意一下，因为这个代码审计的结果是根据危险函数来判别的，所以例如`c.File`这种`Gin`框架中的危险函数就不会被识别到，此题用这个函数可以实现路径穿越，因此对于扫描结果还要报以审慎的态度。

尝试在`rules\readfile.go`增加一些识别功能，但是没有成功
估计需要看一下语法树才能知道规则怎么写？或者需要加别的代码？
自己加的代码(未成功)：
```go
	// 尝试这些不同的写法：
	rule.Add("gin.Context", "File")                      // 不带指针
	rule.Add("*gin.Context", "File")                     // 带指针（当前）
	rule.Add("github.com/gin-gonic/gin.Context", "File") // 完整包路径
```

此外，问AI说gosec支持对二进制文件进行扫描，自己试了一下没有成功

## 审计工具govulncheck

[govulncheck文档](https://golang.ac.cn/doc/tutorial/govulncheck)


### 安装
安装命令：
`go install golang.org/x/vuln/cmd/govulncheck@latest`

我的被安装在了 `C:\Users\######\go\bin`


### 使用命令

对源码进行扫描：

在包含有`go.mod`的文件夹运行以下命令：
`govulncheck ./...`
govulncheck不支持输出到文件中，默认在控制台打印

输出结果示例：
```bash
\i春秋冬季赛2024\Gotar\Gotar>govulncheck ./...
=== Symbol Results ===

Vulnerability #1: GO-2025-3553
    Excessive memory allocation during header parsing in
    github.com/golang-jwt/jwt
  More info: https://pkg.go.dev/vuln/GO-2025-3553
  Module: github.com/golang-jwt/jwt
    Found in: github.com/golang-jwt/jwt@v3.2.2+incompatible
    Fixed in: N/A
    Example traces found:
      #1: utils/jwt.go:25:28: utils.GenerateJWT calls jwt.NewWithClaims
      #2: middleware/auth.go:22:36: middleware.AuthMiddleware calls jwt.ParseWithClaims
      #3: utils/jwt.go:26:27: utils.GenerateJWT calls jwt.Token.SignedString
      #4: utils/jwt.go:5:2: utils.init calls jwt.init

Vulnerability #2: GO-2021-0106
    Path traversal in github.com/whyrusleeping/tar-utils
  More info: https://pkg.go.dev/vuln/GO-2021-0106
  Module: github.com/whyrusleeping/tar-utils
    Found in: github.com/whyrusleeping/tar-utils@v0.0.0-20180509141711-8c6c8ba81d5c
    Fixed in: github.com/whyrusleeping/tar-utils@v0.0.0-20201201191210-20a61371de5b
    Example traces found:
      #1: controllers/file.go:110:25: controllers.extractTar calls tar.Extractor.Extract

Your code is affected by 2 vulnerabilities from 2 modules.
This scan also found 0 vulnerabilities in packages you import and 1
vulnerability in modules you require, but your code doesn't appear to call these
vulnerabilities.
Use '-show verbose' for more details.
```
会对扫描出来的问题有一个简单的介绍，这里可以看见有一个明显的tar-utils的依赖问题


对二进制文件进行扫描：
一样的，加个参数`-mode=binary`，示例：`govulncheck.exe -mode=binary .\GinTest.exe`
