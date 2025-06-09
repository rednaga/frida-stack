# frida-stack

Small frida module for ensuring you get the stack information you wanted.

## What?

Often when using [Frida](https://github.com/frida/frida), I would run into issues
with wanting specific stack traces. Then I realized I didn't have a specific context
window, or the stack traces didn't contain the correct shared libraries in them. This
resulted in me re-writing the same functions all the time.

In other instances, mostly when reverse engineering heavily obfuscated or packed code,
I would have discovered functions or places in memory which had been created without any
exports available. This would lead to questions like, what process/library owned this? Where
am I inside those libraries?

To answer the above questions, I wrapped some of the standard `Thread.Backtrace` functions
and added some scanning of the `Process` memory ranges.

## Installing

```sh
$ npm install frida-stack
```

## Usage

```typescript

import { Stack } from 'frida-stack'

function hook_exit() {
  const _exitPtr = Module.findExportByName('libc.so', '_exit');

  if (_exitPtr) {
    const _exit = new NativeFunction(_exitPtr, 'int', ['int']);

    Interceptor.replace(
      _exitPtr,
      new NativeCallback(
        function (status) {
          console.log(`[+] _exit : ${status} from ${Stack.getModuleInfo(this.context.pc)}`);
	        console.log(Stack.native(this.context)
          return _exit(status);
        },
        'int',
        ['int'],
      ),
    );
  }
}
```

Output:
```
[Pixel 4::com.example.package ]-> [+] _exit : 0 from 0x7713d25000 libexamplesharedlib.so:0x1aae8
0x7713d25000 libexamplesharedlib.so:0x1aae8
```

Now you have a library and the exact offset into the library for reversing.


## License

```
Copyright 2020-2025 Tim 'diff' Strazzere <diff@protonmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```