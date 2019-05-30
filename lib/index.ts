const THUMB_HOOK_REDIRECT_SIZE = 8;
const THUMB_BIT_REMOVAL_MASK = ptr(1).not();

const trampolines: NativePointer[] = [];
const replacements: NativePointer[] = [];

export function makeTrampoline(target: NativePointer): NativePointer {
    const targetAddress = target.and(THUMB_BIT_REMOVAL_MASK);
    const trampoline = Memory.alloc(Process.pageSize);

    Memory.patchCode(trampoline, 128, code => {
        const writer = new ThumbWriter(code, { pc: trampoline });
        const relocator = new ThumbRelocator(targetAddress, writer);

        let n: number;
        do {
            n = relocator.readOne();
        } while (n < THUMB_HOOK_REDIRECT_SIZE);

        relocator.writeAll();

        if (!relocator.eoi) {
            writer.putLdrRegAddress("pc", target.add(n));
        }

        writer.flush();
    });

    trampolines.push(trampoline);

    return trampoline.or(1);
}

export function replace(target: NativePointer, replacement: NativePointer): void {
    const targetAddress = target.and(THUMB_BIT_REMOVAL_MASK);

    Memory.patchCode(targetAddress, 128, code => {
        const writer = new ThumbWriter(code, { pc: targetAddress });
        writer.putLdrRegAddress("pc", replacement);
        writer.flush();
    });

    replacements.push(replacement);
}