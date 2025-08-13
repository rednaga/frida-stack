/**
 * Helper class for getting stack traces and backtraces while debugging with
 * Frida, primarily used for Android.
 * 
 * Modified to fix the java() method to be static as it should be.
 */

import Java from 'frida-java-bridge';

export class Stack {
   
    /**
     * @returns {string} a java stack trace of where this was called
     */
    static java(): string {
        if (!Java.available) {
            throw new Error(`Java is not available`);
        }
        
        let stackString = '';
        Java.perform(() => {
            Java.use('java.lang.Thread')
                .currentThread()
                .getStackTrace()
                .map((stackLayer: string, index: number) => {
                    // Ignore our own creations on the stack (getStackTrace/getThreadStackTrace)
                    if (index > 1) {
                        stackString = stackString.concat(`${index - 1} => ${stackLayer.toString()}\n`);
                    }
                });
        });
        
        return stackString;
    }

    /**
     * @param context in which to get a native backtrace
     * @returns string of backtrace
     */
    static native(context: CpuContext) {
        return (
            Thread.backtrace(context, Backtracer.ACCURATE)
                .map(this.getModuleInfo)
                .join('\n') + '\n'
        );
    }

    /**
     * Return a decorated string, similar to DebugSymbol.fromAddress
     * and Process.getModuleFromAddress, however if those fail we
     * will forcefully look up the address association via the mappings.
     *
     * @param address Address to look up details for.
     * @returns string of relevant data `0x7713d25000 libsharedlib.so:0x1aae8`
     */
    static getModuleInfo(address: NativePointer) {
        const debugSymbol = DebugSymbol.fromAddress(address);

        if (debugSymbol.moduleName) {
            return debugSymbol.toString();
        }

        const builtSymbol = {
            base: ptr(0x0),
            moduleName: '',
            path: '',
            size: 0,
        };

        let ranges = Process.enumerateRanges('').filter(
            (range) => range.base <= address && range.base.add(range.size) >= address,
        );

        ranges.forEach((range) => {
            if (range.file) {
                builtSymbol.path = range.file.path;
                const moduleNameChunks = range.file.path.split('/');
                builtSymbol.moduleName = moduleNameChunks[moduleNameChunks.length - 1];
                builtSymbol.base = range.base.sub(range.file.offset);
            }
        });

        ranges = Process.enumerateRanges('').filter(
            (range) => range.base <= builtSymbol.base && range.base.add(range.size) >= builtSymbol.base,
        );

        ranges.forEach((range) => {
            if (builtSymbol.base === ptr(0x0) || builtSymbol.base < range.base) {
                builtSymbol.base = range.base;
            }
            builtSymbol.size += range.size;
        });

        return `${builtSymbol.base} ${builtSymbol.moduleName}:${address.sub(builtSymbol.base)}`;
    }
}
