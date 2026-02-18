> This article was first published on the [tttang Community](https://tttang.com/archive/1889/).

## Introduction
In the previously published article ["Reverse Engineering WeChat on macOS: Building a Forensic Tool"](https://blog.imipy.com/post/reverse-engineering-wechat-on-macos--building-a-forensic-tool.html), I used the Frida tool to extract chat database key from memory. The Frida `ObjC` APIs are primarily provided by [frida-objc-bridge](https://github.com/frida/frida-objc-bridge). Since there’s limited documentation on this topic online, I decided to explore its internal workings out of curiosity. This article starts with an understanding of the `Objective-C Runtime`, including concepts like **Sending Messages** and **Method Swizzling**, and then the internal implementation of `frida-objc-bridge`, especially the `choose` method. Finally, I will implement a tool using `Objective-C` to inject a dylib into remote processes.

## Objective-C Runtime

The [Objective-C Runtime](https://developer.apple.com/documentation/objectivec/objective-c_runtime?language=objc) is a runtime library that provides support for the dynamic properties of the Objective-C language, and as such is linked to by all Objective-C apps. Objective-C runtime library support functions are implemented in the shared library found at `/usr/lib/libobjc.A.dylib`.

### Sending Messages

Objective-C is a dynamic language, meaning object types are determined at runtime, including function name lookups.

In Objective-C, calling a class method involves sending a message to an object, which includes the method name and the expected parameters. At runtime, the corresponding function is looked up by name and invoked. This requires the compiled code to retain all relevant object method names for runtime use.

---

```objectivec
// message_send_demo.m
#import <Foundation/Foundation.h>

@interface AClass : NSObject
@end
@implementation AClass : NSObject
@end

int main() {
  id a = @"this is NSString";
  [a characterAtIndex:1];

  id acls = [AClass new];
  [acls characterAtIndex:2];
}
```

Even though the objc code above attempts to call a non-existent method, it compiles successfully but throws an exception at runtime:

```bash
$ clang -framework Foundation message_send_demo.m -o demo
$ ./demo
2023-04-18 11:38:07.537 demo[15135:508503] -[AClass characterAtIndex:]: unrecognized selector sent to instance 0x156e0bbc0
2023-04-18 11:38:07.538 demo[15135:508503] *** Terminating app due to uncaught exception 'NSInvalidArgumentException', reason: '-[AClass characterAtIndex:]: unrecognized selector sent to instance 0x156e0bbc0'
*** First throw call stack:
(
        0   CoreFoundation                      0x00000001c4d35148 __exceptionPreprocess + 240
        1   libobjc.A.dylib                     0x00000001c4a7fe04 objc_exception_throw + 60
        2   CoreFoundation                      0x00000001c4dc8ef8 -[NSObject(NSObject) __retain_OA] + 0
        3   CoreFoundation                      0x00000001c4c94494 ___forwarding___ + 1764
        4   CoreFoundation                      0x00000001c4c93cf0 _CF_forwarding_prep_0 + 96
        5   demo                                0x0000000104797f64 main + 84
        6   dyld                                0x000000010482508c start + 520
)
libc++abi: terminating with uncaught exception of type NSException
[1]    15135 abort      ./demo
```

Method calls in Objective-C are performed using the function `objc_msgSend(void /* id self, SEL op, ... */)`, which sends a message to the object. For instance, `[a characterAtIndex:1]` translates to `objc_msgSend(id self, @selector(characterAtIndex:), 1)` at compile time. To understand this further, let’s analyze the id and SEL data types, uncovering the mechanics of **Sending Messages** in Objective-C.

---

The [id](https://developer.apple.com/documentation/objectivec/id?language=objc) is a pointer to any (`NSObject`) class instance(Unlike void* in C, it points to a known structure). The `id` type is defined in [runtime/objc.h](https://github.com/apple-oss-distributions/objc4/blob/main/runtime/objc.h#L38) as:

```c
/// An opaque type that represents an Objective-C class.
typedef struct objc_class *Class;

/// Represents an instance of a class.
struct objc_object {
    Class _Nonnull isa  OBJC_ISA_AVAILABILITY;
};

/// A pointer to an instance of a class.
typedef struct objc_object *id;
```

Here, id is a pointer to an `objc_object`, whose `isa` field points to the `objc_class` structure. The `objc_class` structure is defined in [runtime.h](https://github.com/opensource-apple/objc4/blob/master/runtime/runtime.h#L55):

```c
struct objc_class {
    Class isa  OBJC_ISA_AVAILABILITY;

#if !__OBJC2__
    Class super_class                                        OBJC2_UNAVAILABLE;
    const char *name                                         OBJC2_UNAVAILABLE;
    long version                                             OBJC2_UNAVAILABLE;
    long info                                                OBJC2_UNAVAILABLE;
    long instance_size                                       OBJC2_UNAVAILABLE;
    struct objc_ivar_list *ivars                             OBJC2_UNAVAILABLE;
    struct objc_method_list **methodLists                    OBJC2_UNAVAILABLE;
    struct objc_cache *cache                                 OBJC2_UNAVAILABLE;
    struct objc_protocol_list *protocols                     OBJC2_UNAVAILABLE;
#endif

} OBJC2_UNAVAILABLE;
```

The `objc_class` structure includes a name (`name`), a pointer to its superclass (`super_class`), a pointer to instance variables (`ivars`), a method list (`methodLists`), a cache (`cache`), and finally, a pointer to the protocol list (`protocols`).

`objc_method_list`: Think of it as an array, with each element being an `objc_method` structure:

```c
struct objc_method {
    SEL method_name                                          OBJC2_UNAVAILABLE;
    char *method_types                                       OBJC2_UNAVAILABLE;
    IMP method_imp                                           OBJC2_UNAVAILABLE;
}                                                            OBJC2_UNAVAILABLE;

struct objc_method_list {
    struct objc_method_list *obsolete                        OBJC2_UNAVAILABLE;

    int method_count                                         OBJC2_UNAVAILABLE;
#ifdef __LP64__
    int space                                                OBJC2_UNAVAILABLE;
#endif
    /* variable length structure */
    struct objc_method method_list[1]                        OBJC2_UNAVAILABLE;
}                                                            OBJC2_UNAVAILABLE;
```

Key fields include:
- method_name: `SEL(@selector)`.
- method_types: [**Type Encodings**](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/ObjCRuntimeGuide/Articles/ocrtTypeEncodings.html)。
- method_imp: a pointer to the actual method's implementation address and can accept a variable number of arguments. The first argument represents the object of type `id`, and the second is the selector.

[SEL](https://developer.apple.com/documentation/objectivec/sel): A [Selector](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/ObjectiveC/Chapters/ocSelectors.html) uniquely identifying a method. Its definition:
```c
typedef struct objc_selector *SEL;
```

When calling `objc_msgSend`, the function uses the `isa` pointer to traverse the `methodLists`, searching for the `method_name` specified by the selector. Below is a visual representation of the structure and lookup process:

![image](https://github.com/user-attachments/assets/5983c340-f8be-49de-bc0d-d500f127b724)

## Method Swizzling

Frida uses **Method Swizzling** to inject or modify `ObjC` methods. A common implementation is:

```objectivec
...
void hookMethod(Class originalClass, SEL originalSelector, Class swizzledClass, SEL swizzledSelector){
    Method originalMethod = class_getInstanceMethod(originalClass, originalSelector);
    Method swizzledMethod = class_getInstanceMethod(swizzledClass, swizzledSelector);
    if (originalMethod && swizzledMethod){
        method_exchangeImplementations(originalMethod, swizzledMethod);
    }
}
...
@interface NSObject (TargetClass)
+ (void) hookApp;
@end

@implementation NSObject (TargetClass)
- (void)hook_hello:(char)arg2
{
	// TODO ...
	// [self hook_hello:arg2] now hook_hello -> hello imp
}

+ (void) hookApp
{
    hookMethod(objc_getClass("TargetClass"),
               @selector(hello:),
               [self class],
               @selector(hook_hello:));
}
@end
```

In this example, we use [Categories](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/ProgrammingWithObjectiveC/CustomizingExistingClasses/CustomizingExistingClasses.html) to extend the `TargetClass` and swap the implementations of `hello:` and `hook_hello:` using `method_exchangeImplementations`. 

Post-swapping, calling `[self hook_hello:arg2]` invokes the original hello: method due to the swapped pointers. A visual representation:

![image](https://github.com/user-attachments/assets/c957b59a-4906-45d7-a49e-280169ee4d6f)

---

There is another approach that does not require defining class `Categories`. Instead, the original function's `imp` pointer can be replaced using `method_setImplementation`.

```objectivec
static IMP real_isEqualToString = NULL;
static BOOL custom_isEqualToString(id self, SEL _cmd, NSString *s) {
	// TODO ...
	return ((BOOL(*)(id, SEL, NSString *))real_isEqualToString)(self, _cmd, s);
}

real_isEqualToString = method_setImplementation(
      class_getInstanceMethod(NSClassFromString(@"__NSCFString"),
                              @selector(isEqualToString:)),
      (IMP)custom_isEqualToString);
```

Here, the `isEqualToString:` implementation is replaced by `custom_isEqualToString`. The original implementation is stored in `real_isEqualToString`. A visual representation:

![image](https://github.com/user-attachments/assets/a0143af6-fdd4-4077-b71a-289194964aca)

## **Frida**

The Frida project operates at a relatively low level and is quite complex. I learned about Frida's design and structure through EvilPan's [Frida Internal](https://evilpan.com/2022/04/05/frida-internal/) series of articles. Frida can be divided into four layers based on its encapsulation hierarchy:

1. **Inline-hook framework at the CPU instruction set level:** `frida-gum`  
    - Includes inline hooking, code tracing with Stalker, memory access monitoring via `MemoryAccessMonitor`, as well as features like symbol resolution, stack unwinding, memory scanning, dynamic code generation, and relocation.
2. JavaScript engine integration for script extensibility: `gum-js`  
3. Runtime process injection, script loading, and RPC communication management: `frida-core`
4. JavaScript modules and their interfaces tailored for specific runtime environments: Examples include `frida-java-bridge`, `frida-objc-bridge`, and others.

### Process Injection

In the Darwin environment, the injection function in `frida-core` is [_frida_darwin_helper_backend_inject_into_task](https://github.com/frida/frida-core/blob/main/src/darwin/frida-helper-backend-glue.m#L2209). This function is quite complex. In simple terms, it generates a piece of shellcode that essentially performs an operation similar to `dlopen("frida-agent.dylib")`, and then, using a series of Mach APIs, creates a thread in the target process to execute the shellcode.

### **Frida Objc Bridge**

`frida-objc-bridge` is essentially implemented as a hack targeting the runtime of the corresponding high-level language, built on top of `gum-js`. These are collectively referred to as the bridges for their respective languages. In the runtime, [gumjs](https://github.com/frida/frida-gum/blob/main/bindings/gumjs/runtime/objc.js) introduces it (`Frida._objc = require('frida-objc-bridge')`). This is the foundation for the `ObjC.*` interfaces we use when writing Frida JavaScript scripts.

#### /lib/api.js

The `api.js` file loads the `libobjc.A.dylib` dynamic library to import Objective-C APIs, such as `objc_getClassList`, `class_getInstanceMethod`, and others.

```jsx
...
function getApi() {
...
    const pending = [
        {
            module: "libsystem_malloc.dylib",
            functions: {
                "free": ['void', ['pointer']]
            }
        }, {
            module: "libobjc.A.dylib",
            functions: {
                "objc_msgSend": function (address) {
                    this.objc_msgSend = address;
                },
                "objc_msgSend_stret": function (address) {
                    this.objc_msgSend_stret = address;
                },
                "objc_msgSend_fpret": function (address) {
                    this.objc_msgSend_fpret = address;
                },
                "objc_msgSendSuper": function (address) {
                    this.objc_msgSendSuper = address;
                },
                "objc_msgSendSuper_stret": function (address) {
                    this.objc_msgSendSuper_stret = address;
                },
                "objc_msgSendSuper_fpret": function (address) {
                    this.objc_msgSendSuper_fpret = address;
                },
                "objc_getClassList": ['int', ['pointer', 'int']],
                "objc_lookUpClass": ['pointer', ['pointer']],
                "objc_allocateClassPair": ['pointer', ['pointer', 'pointer', 'pointer']],
                "objc_disposeClassPair": ['void', ['pointer']],
                "objc_registerClassPair": ['void', ['pointer']],
                "class_isMetaClass": ['bool', ['pointer']],
                "class_getName": ['pointer', ['pointer']],
                "class_getImageName": ['pointer', ['pointer']],
                "class_copyProtocolList": ['pointer', ['pointer', 'pointer']],
                "class_copyMethodList": ['pointer', ['pointer', 'pointer']],
                "class_getClassMethod": ['pointer', ['pointer', 'pointer']],
                "class_getInstanceMethod": ['pointer', ['pointer', 'pointer']],
                "class_getSuperclass": ['pointer', ['pointer']],
                "class_addProtocol": ['bool', ['pointer', 'pointer']],
                "class_addMethod": ['bool', ['pointer', 'pointer', 'pointer', 'pointer']],
                "class_copyIvarList": ['pointer', ['pointer', 'pointer']],
                "objc_getProtocol": ['pointer', ['pointer']],
                "objc_copyProtocolList": ['pointer', ['pointer']],
                "objc_allocateProtocol": ['pointer', ['pointer']],
                "objc_registerProtocol": ['void', ['pointer']],
                "protocol_getName": ['pointer', ['pointer']],
                "protocol_copyMethodDescriptionList": ['pointer', ['pointer', 'bool', 'bool', 'pointer']],
                "protocol_copyPropertyList": ['pointer', ['pointer', 'pointer']],
                "protocol_copyProtocolList": ['pointer', ['pointer', 'pointer']],
                "protocol_addProtocol": ['void', ['pointer', 'pointer']],
                "protocol_addMethodDescription": ['void', ['pointer', 'pointer', 'pointer', 'bool', 'bool']],
                "ivar_getName": ['pointer', ['pointer']],
                "ivar_getTypeEncoding": ['pointer', ['pointer']],
                "ivar_getOffset": ['pointer', ['pointer']],
                "object_isClass": ['bool', ['pointer']],
                "object_getClass": ['pointer', ['pointer']],
                "object_getClassName": ['pointer', ['pointer']],
                "method_getName": ['pointer', ['pointer']],
                "method_getTypeEncoding": ['pointer', ['pointer']],
                "method_getImplementation": ['pointer', ['pointer']],
                "method_setImplementation": ['pointer', ['pointer', 'pointer']],
                "property_getName": ['pointer', ['pointer']],
                "property_copyAttributeList": ['pointer', ['pointer', 'pointer']],
                "sel_getName": ['pointer', ['pointer']],
                "sel_registerName": ['pointer', ['pointer']],
                "class_getInstanceSize": ['pointer', ['pointer']]
            },
            optionals: {
                "objc_msgSend_stret": 'ABI',
                "objc_msgSend_fpret": 'ABI',
                "objc_msgSendSuper_stret": 'ABI',
                "objc_msgSendSuper_fpret": 'ABI',
                "object_isClass": 'iOS8'
            }
        },
			...
    ];
}
```

#### /lib/fastpaths.js

The `/lib/fastpaths.js` file implements a `choose` method that can search for ObjC instances of a class in memory. The source code is primarily divided into two parts: C and JavaScript. The JavaScript part handles calling and encapsulating the C code:

```jsx
...
function compileModule() {
    const {
        objc_getClassList,
        class_getSuperclass,
        class_getInstanceSize,
    } = getApi();

    const selfTask = Memory.alloc(4);
    selfTask.writeU32(Module.getExportByName(null, 'mach_task_self_').readU32());

    const cm = new CModule(code, {
        objc_getClassList,
        class_getSuperclass,
        class_getInstanceSize,
        malloc_get_all_zones: Module.getExportByName('/usr/lib/system/libsystem_malloc.dylib', 'malloc_get_all_zones'),
        selfTask,
    });

    const _choose = new NativeFunction(cm.choose, 'pointer', ['pointer', 'bool', 'pointer']);
    const _destroy = new NativeFunction(cm.destroy, 'void', ['pointer']);

    return {
        handle: cm,
        choose(klass, considerSubclasses) {
            const result = [];

            const countPtr = Memory.alloc(4);
            const matches = _choose(klass, considerSubclasses ? 1 : 0, countPtr);
            try {
                const count = countPtr.readU32();
                for (let i = 0; i !== count; i++)
                    result.push(matches.add(i * pointerSize).readPointer());
            } finally {
                _destroy(matches);
            }

            return result;
        },
    };
}
```

Explanation of the key code:

- `selfTask` calls `mach_task_self()` to obtain the Task port of the current process.  
- The `malloc_get_all_zones` function is imported from the `/usr/lib/system/libsystem_malloc.dylib` dynamic library. Its main purpose is to retrieve all heap memory regions.  
- `_choose` is the `choose` function from the C code, referenced using `NativeFunction`. It is then wrapped as `choose(klass, considerSubclasses)`, which becomes the `ObjC.choose(ObjC.classes.NSString)` interface we use.  

Trace the internals of the `choose` function:

1. Using `objc_getClassList`, it iterates through all classes and their superclasses. If a class matches the target class, it is inserted into the `ctx.classes` hash table.

```c
typedef struct _ChooseContext
{
    GHashTable *classes;
    GArray *matches;
} ChooseContext;
...
Class *klass; // Target class
ChooseContext ctx;
...
collect_subclasses(klass, ctx.classes);
...
static void collect_subclasses(Class klass, GHashTable *result)
{
	Class *all_classes;
	count = objc_getClassList(all_classes, count);
	for (i = 0; i != count; i++)
    {
        Class candidate = all_classes[i];
        Class c;

        c = candidate;
        do
        {
            if (c == klass)
            {
                g_hash_table_insert(result, candidate, GSIZE_TO_POINTER(class_getInstanceSize(candidate)));
                break;
            }
                // class_getSuperclass: Return the class superclass
                // https://developer.apple.com/documentation/objectivec/1418498-class_getsuperclass?language=objc
            c = class_getSuperclass(c);
        } while (c != NULL);
    }
}
```

2. Get all heap memory regions in the current process.

```c
...
vm_address_t *malloc_zone_addresses;
unsigned malloc_zone_count;
malloc_zone_count = 0;
malloc_get_all_zones(mach_task_self(), read_local_memory, &malloc_zone_addresses, &malloc_zone_count);
...
```

3. Enumerate the allocated spaces in the heap:  

`zone->introspect->enumerator(...)` enumerates all memory blocks in the specified memory region. `MALLOC_PTR_IN_USE_RANGE_TYPE` indicates that only the memory blocks that are in use (allocated) will be enumerated.

```c
for (i = 0; i != malloc_zone_count; i++)
{
    vm_address_t zone_address = malloc_zone_addresses[i];
    malloc_zone_t *zone = (malloc_zone_t *)zone_address;
		...
		zone->introspect->enumerator(mach_task_self(), &ctx, MALLOC_PTR_IN_USE_RANGE_TYPE, zone_address, read_local_memory, collect_matches_in_ranges)
}
```

4. Collect class instances: Enumerate the `ranges`, and for any address that points to a valid `isa` and corresponds to a class in the context's `classes`, add the instance to the `matches` list.

```c
static void collect_matches_in_ranges(task_t task,
													void *user_data,
                          unsigned type,
                          vm_range_t *ranges,
                          unsigned count)
{
    ChooseContext *ctx = user_data;
    GHashTable *classes = ctx->classes;
    unsigned i;

    for (i = 0; i < count; i++)
    {
        vm_range_t *range = &ranges[i];
				gconstpointer candidate = GSIZE_TO_POINTER(range->address);
        isa = *(gconstpointer *)candidate;
				...
        instance_size = GPOINTER_TO_UINT(g_hash_table_lookup(classes, isa));
        if (instance_size != 0 && range->size >= instance_size)
        {
            g_array_append_val(ctx->matches, candidate);
        }
    }
}
```

These are all the internal details of the `choose` method.

Next, I will demonstrate how to use Objective-C to inject a dynamic library into a target process, locate CLASS instances in the target process's memory, and execute their methods.

### Choose Demo

- Target Demo:

```objectivec
// example_target.m
#import <Foundation/Foundation.h>

@interface TEST : NSObject
- (void)dododo;
@end

@implementation TEST
- (void)dododo {
  NSLog(@"you did it!");
}
@end

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    NSLog(@"pid -> %d", getpid());
    // create TEST instrance
    TEST *t = [[TEST alloc] init];
    while (YES) {}
  }
  return 0;
}
```

- Iterate through memory to locate instances of the `TEST` class and execute the `dododo` method:

```objectivec
// example_choose.m
// @Base: https://gist.github.com/samdmarshall/17f4e66b5e2e579fd396

#import <Foundation/Foundation.h>
#import <mach/mach_vm.h>
#import <malloc/malloc.h>
#import <objc/message.h>
#import <objc/runtime.h>

#if defined(__arm64__)
#define OBJC_ISA_MASK 0xffffffff8ULL
#elif defined(__i386__) // TODO
#define OBJC_ISA_MASK 0x7ffffffffff8ULL
#endif

// TODO Target class
#define CLASS "TEST"

Class cls;
size_t cls_size;

void CanHasObjects(task_t task, void *context, unsigned type,
                   vm_range_t *ranges, unsigned count) {
  unsigned i;
  for (i = 0; i < count; i++) {
    vm_range_t *range = &ranges[i];
    uintptr_t *address = ((uintptr_t *)range->address);
    uintptr_t *isa;

    if (address == NULL) {
      continue;
    }

    isa = (uintptr_t *)address[0];
#ifdef OBJC_ISA_MASK
    isa = (uintptr_t *)((unsigned long long)isa & OBJC_ISA_MASK);
#endif

    if (isa > 0 && range->size >= sizeof(Class) && cls == (Class)isa) {
#ifdef DEBUG
      printf("[+] fond isa(%p)->'%s' instance %p \n", isa,
             object_getClassName((Class)isa), address);
#endif
      // TODO run taget class function
      ((void (*)(id, SEL))objc_msgSend)((__bridge id)address,
                                        @selector(dododo));
    }
  }
}

static void __attribute__((constructor)) initialize(void) {
  @autoreleasepool {
    cls = NSClassFromString([NSString stringWithFormat:@"%s", CLASS]);
    if (cls == Nil) {
#ifdef DEBUG
      printf("[-] Class not found\n");
#endif
      return;
    }

    cls_size = class_getInstanceSize(cls);
    if (cls_size == 0) {
#ifdef DEBUG
      printf("[-] Class Instance size is %zu\n", cls_size);
#endif
      return;
    }

#ifdef DEBUG
    printf("[+] Class %p Instance size is %zu\n", cls, cls_size);
#endif

    vm_address_t *zones;
    unsigned count, i = 0;
    kern_return_t r =
        malloc_get_all_zones(mach_task_self(), NULL, &zones, &count);
    if (r == KERN_SUCCESS) {
      for (i = 0; i < count; i++) {
        vm_address_t zone_address = zones[i];
        malloc_zone_t *zone = (malloc_zone_t *)zone_address;

        if (zone != NULL && zone->introspect != NULL) {
          zone->introspect->enumerator(mach_task_self(), NULL,
                                       MALLOC_PTR_IN_USE_RANGE_TYPE,
                                       zone_address, NULL, &CanHasObjects);
        }
      }
    }
  }
}
```

- [inx](https://github.com/BreakOnCrash/inx) is an open-source tool I developed. It allows you to inject `.dylib` files into target processes on macOS (both arm64 and x86_64).

- Run And Test

```bash
$ clang -shared -framework Foundation examples/example_dylib.m -o tests/libexample.dylib
$ clang -framework Foundation examples/example_target.m  -o tests/example_target
# run target process
$ ./example_target
# inject libchoose.dylib
$ sudo ./bin/inx [] /path/libchoose.dylib
```
![](https://github.com/user-attachments/assets/933031b0-f100-4c27-8c4a-ebc1a30b791e)

## Reference

- [https://developer.apple.com/documentation/objectivec/objective-c_runtime](https://developer.apple.com/documentation/objectivec/objective-c_runtime?language=objc)
- [https://tech.meituan.com/2015/08/12/deep-understanding-object-c-of-method-caching.html](https://tech.meituan.com/2015/08/12/deep-understanding-object-c-of-method-caching.html)
- [https://evilpan.com/2022/04/05/frida-internal/](https://evilpan.com/2022/04/05/frida-internal/)
- [https://www.todayios.com/find-ios-heap-object/](https://www.todayios.com/find-ios-heap-object/)

<!-- ##{"timestamp":1681660800}## -->