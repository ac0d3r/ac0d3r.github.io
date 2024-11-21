> This article was first published on the [RedTeam.Site Community](https://mp.weixin.qq.com/s/dC8489jQ3jEC1AUrCBE6pw).

## Existing Solution

[https://github.com/allen1881996/WeChat-Data-Analysis](https://github.com/allen1881996/WeChat-Data-Analysis)

1. Open the desktop version of WeChat on your macOS system (but do not login).
2. Open the Terminal and enter the following command:
	```bash
	lldb -p $(pgrep WeChat)  
	```
3. Set a breakpoint using the command:
	```lldb
	br set -n sqlite3_key
	```
4. Enter c and press Enter to continue execution.
5. Log in to it.
6. After logging in, enter the following command to read memory:
	```lldb
	memory read --size 1 --format x --count 32 $rsi
	```
    - For ARM architecture, replace `$rsi` with `$x1`:
		```lldb
		memory read --size 1 --format x --count 32 $x1
		```
![image](https://github.com/user-attachments/assets/e59f270c-7793-413b-82aa-240f9b8981c9)

7. Parse the data using code to extract the key:

```python
ori_key = """
0x60000241e920: 0x11 0x22 0x33 0x44 0x55 0xaa 0xbb 0xcc
0x60000241e928: 0x11 0x22 0x33 0x44 0x55 0xaa 0xbb 0xcc
0x60000241e930: 0x11 0x22 0x33 0x44 0x55 0xaa 0xbb 0xcc
0x60000241e938: 0x11 0x22 0x33 0x44 0x55 0xaa 0xbb 0xcc
"""

key = '0x' + ''.join(i.partition(':')[2].replace('0x', '').replace(' ', '') for i in ori_key.split('\n')[1:5])
print(key)
```

WeChat chat database file storage path: `~/Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat/[version]/[uuid]/Message/*.db`

Use **DB Browser for SQLite** to open and view the chat database:

![image](https://github.com/user-attachments/assets/ad10511a-0b1e-4ce2-82ad-6728cdb343b5)

## Exploring the Internal Storage of WeChat Chat

WeChat on macOS uses WCDB to manage its chat data. [WCDB](https://github.com/Tencent/wcdb) is an open-source project by Tencent, built on top of [SQLCipher](https://github.com/sqlcipher/sqlcipher).

In [SQLCipher](https://github.com/sqlcipher/sqlcipher), the [sqlite3_key](https://github.com/sqlcipher/sqlcipher/blob/master/src/crypto.c#L914) function is used to open encrypted databases. WCDB encapsulates this function within the [setCipherKey](https://github.com/Tencent/wcdb/wiki/iOS-macOS%e4%bd%bf%e7%94%a8%e6%95%99%e7%a8%8b#%E5%8A%A0%E5%AF%86) method."

```c
int sqlite3_key(sqlite3 *db, const void *pKey, int nKey)
```

This explains why, by setting a breakpoint at the `sqlite3_key` function and reading `rsi` (the second parameter), we can obtain the encryption `*pKey`.

## Thought Process for Building a Forensic Tool

### Decoding from File

Find a Sample Objective-C Code for Opening an Encrypted Database in the WCDB Wiki：

```objective-c
WCTDatabase *database = [[WCTDatabase alloc] initWithPath:path];
NSData *password = [@"MyPassword" dataUsingEncoding:NSASCIIStringEncoding];
[database setCipherKey:password];
```

Use the `Frida` tool for dynamic analysis of WeChat, Trace the operations of the `WCTDatabase` class:

```bash
$ frida-trace -m "*[WCTDatabase *]" "WeChat"
...
3643 ms  -[WCTDatabase initWithPath:0x6000029d4540]
3643 ms  -[WCTDatabase setTag:0x5]
3643 ms  -[WCTDatabase setCipherKey:0x600001246190 andCipherPageSize:0x400 andRaw:0x1]
3643 ms  -[WCTDatabase createTableAndIndexesOfName:0x1071fa9f8 withClass:0x107713dc8]
3645 ms  -[WCTDatabase getTableOfName:0x1071fa9f8 withClass:0x107713dc8]
...
4044 ms  -[WCTDatabase initWithPath:0x115058b60]
4044 ms  -[WCTDatabase setTag:0xd]
4044 ms  -[WCTDatabase setCipherKey:0x600001246190 andCipherPageSize:0x400 andRaw:0x1]
4044 ms  -[WCTDatabase createTableAndIndexesOfName:0x107207a58 withClass:0x10771f628]
4045 ms  -[WCTDatabase getTableOfName:0x107207a58 withClass:0x10771f628]
4182 ms  -[WCTDatabase isTableExists:0x60000075b400]
...
79122 ms  -[WCTDatabase backupWithCipher:0x600001246190]
```

Read the value of the `setCipherKey` parameter. From the example code, it can be determined that `0x600001246190` is an `NSData` object. The content is retrieved in Frida:

```js
// Edit WCTDatabase/setCipherKey_andCipherPageSize_andRaw_.js
...
onEnter(log, args, state) {
  log(`-[WCTDatabase setCipherKey:${args[2]} andCipherPageSize:${args[3]} andRaw:${args[4]}]`);

	var nsd = new ObjC.Object(args[2]); // Convert to Objc object
  log(`key ==> nsdata:=${nsd}=`);
  // nsdata.bytes 2 hex string
  log(hexdump(nsd.bytes(), {
    offset: 0,
    length: nsd.length(),
    header: true,
    ansi: true
  }));
},
...
```

![image](https://github.com/user-attachments/assets/a4fcba31-d388-4f3e-93c1-d6d48b150399)

The key is the same as before,the WCTDatabase.setCipherKey function is the place where the key is initialized.

Using `Hopper` to reverse engineer, we find the `MessageDB.setupDB` symbol, which we can infer is responsible for setting up the message database:

```objective-c
r0 = @class(WCDBHelper);
r0 = [r0 CipherKey];
...
[*(r21 + 0x8) setTag:*(int32_t *)(r21 + 0x18)];
[*(r21 + 0x8) setCipherKey:var_78 andCipherPageSize:r28 andRaw:0x1];
...
```

The key managed by `WCDBHelper.CipherKey` is obtained from `AccountStorage`. Simplified pseudocode:

```objective-c
...
a = [[MMServiceCenter defaultCenter] getService: [AccountStorage class]]
i = [[a GetDBEncryptInfo] m_dbEncryptKey]
```

Analyze the `AccountStorage` class. In its `init` method, the database configuration file path is provided. Use `PBCoder` to decode `DBEncryptInfo` from the file:

```objective-c
rax = [PathUtility GetAccountSettingDbPath];
rax = [rax retain];
rcx = *ivar_offset(m_dbEncryptInfoPath);
...
rax = [PBCoder decodeObjectOfClass:[DBEncryptInfo class] fromFile:r13->m_dbEncryptInfoPath];
rax = [rax retain];
rbx = *ivar_offset(m_dbEncryptInfo);
```

Hook to retrieve the database configuration file:

```jsx
// Edit PathUtility/GetAccountSettingDbPath.js
onLeave(log, retval, state) {
  var ret = new ObjC.Object(retval);
  log(`return value: ${ret}==`);
}
```
The printed content is: `~/Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat/[version]/[uuid]/Account/setting_db.data`.

What is `PBCoder` and how does it decode data? By searching, I found [an issue in the Tencent open-source MMKV project](https://github.com/Tencent/MMKV/issues/42#issuecomment-424976201), which reveals that pbcoding is based on `protobuf` (Protocol Buffers) for archiving objects.

Using the `protoc --decode_raw < setting_db.data` command to decode the file, we can see three properties: the first property likely represents the key, the second is unknown, and the third is the timestamp:

![image](https://github.com/user-attachments/assets/b8301c5d-08bd-4045-acd0-4bf85dfa3dc7)

Can we bypass the internal decoding process and use Frida to call the `PBCoder` decryption function:
```jsx
// debug.js
// frida WeChat --debug -l tests/debug.js
var path = ObjC.classes.NSString.stringWithString_("wechatOE/setting_db.data");
var key = ObjC.classes.PBCoder["+ decodeObjectOfClass:fromFile:"](ObjC.classes.DBEncryptInfo, path)
var data = key['- m_dbEncryptKey']();
hexdump(data.bytes(), { offset: 0, length: data.length() });
```

It cannot be decoded. After running the `decodeObjectOfClass` function, there is still additional logic to be executed.

Since I couldn't find any relevant clues through reverse engineering, I’ll have to abandon this approach for now.

### Reading from Memory

After the reverse engineering analysis above, retrieving the key from memory is quite easy because `DBEncryptInfo` is a singleton (this has been confirmed through multiple tests). By dumping the value of its `m_dbEncryptKey(NSData)`, the key can be obtained:

![image](https://github.com/user-attachments/assets/720c59c9-01ed-4ca0-bfd3-d9a4c2a66425)

## Building a Forensic Tool

Package the script into an executable using [frida-go](https://github.com/frida/frida-go).

```go
package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/frida/frida-go/frida"
)

func main() {
	fmt.Println(Key())
}

var js = `
var key = ObjC.chooseSync(ObjC.classes.DBEncryptInfo)[0];
var data = key['- m_dbEncryptKey']();
console.log(hexdump(data.bytes(), { offset: 0, length: data.length(), header: false, ansi: false }));
`

type Log struct {
	Type    string `json:"type,omitempty"`
	Level   string `json:"level,omitempty"`
	Payload string `json:"payload,omitempty"`
}

func Key() (string, error) {
	var key string
	c := make(chan struct{}, 1)

	mgr := frida.NewDeviceManager()
	dev, err := mgr.LocalDevice()
	if err != nil {
		return "", err
	}

	session, err := dev.Attach("WeChat", nil)
	if err != nil {
		return "", err
	}

	script, err := session.CreateScript(js)
	if err != nil {
		return "", err
	}

	script.On("message", func(msg string) {
		defer func() {
			c <- struct{}{}
		}()

		m := Log{}
		err := json.Unmarshal([]byte(msg), &m)
		if err == nil {
			key = parse(m.Payload)
		}
	})

	if err := script.Load(); err != nil {
		return "", err
	}

	<-c
	return key, nil
}

func parse(payload string) string {
	var r strings.Builder
	r.WriteString("0x")

	data := strings.Split(payload, "\n")
	if len(data) == 0 {
		return ""
	}
	for i := range data {
		v := strings.Split(data[i], "  ")
		if len(v) != 3 {
			continue
		}
		key := strings.ReplaceAll(v[1], " ", "")
		r.WriteString(key)
	}
	if r.Len() == 2 {
		return ""
	}
	return r.String()
}
```
I got the chat key 🎉:
![image](https://github.com/user-attachments/assets/b45d8772-c44d-481b-ac77-81429b98dd72)

### Tool Optimization

```bash
$ ll wechatoe
-rwxr-xr-x  1 whoami  staff    75M  1 17 17:27 wechatoe
```

Because it contains the embedded Frida dynamic library, the compiled file is very large. In the future, a custom tool will be implemented using Objective-C.


## How to Defend Against It

Due to the limitations of macOS [Hardened Runtime](https://developer.apple.com/documentation/security/hardened_runtime), even if malicious programs use `task_for_pid` API, they cannot control the target process (disabling `SIP` allows it to work).

However, many macOS users install custom plugins for WeChat, and when a plugin is installed, the application needs to be `re-signed`. This process removes the runtime flag: 

![image](https://github.com/user-attachments/assets/4be222c1-ca71-4579-bf29-0b84d03dc8b8)

To preserve the Hardened Runtime, the `--options runtime` flag must be added during re-signing to enable the enhanced runtime protection.

<!-- ##{"timestamp":1673957160}## -->