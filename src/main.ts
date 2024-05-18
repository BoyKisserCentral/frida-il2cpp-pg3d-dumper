import "frida-il2cpp-bridge";
import * as fs from 'fs';

declare global {
    var IL2CPP_EXPORTS: Record<string, () => NativePointer>;
}

const patterns = {
    il2cpp_domain_get_assemblies: "40 53 48 83 EC 20 48 8B DA E8 ?? ?? ?? ?? 48 8B 48 08"
};

globalThis.IL2CPP_EXPORTS = {
    il2cpp_domain_get_assemblies: () => {
        return Memory.scanSync(Il2Cpp.module.base, Il2Cpp.module.size, patterns.il2cpp_domain_get_assemblies)[0].address;
    }
};

function clean_from_sys(str: string) {
    return str.replaceAll(",", ", ").replaceAll("System.", "");
}

function intermediary(): void {
    Il2Cpp.perform(() => {
        let out_arr: string[] = []
        console.log("Performing custom Il2Cpp.dump()");
        Il2Cpp.domain.assemblies.forEach((assembly) => {
            console.log(`Dumping ${assembly.name}.dll`);
            assembly.image.classes.forEach((c) => {
                let has_valid_parent = c.parent && c.parent.name != "Object" && c.parent.name != "Enum" && c.parent.name != "ValueType";
                let output_string = "";
                let interface_construct = "";
                let iface_count = 0;
                c.interfaces.forEach((i) => {
                    interface_construct += i.name;
                    if (iface_count < c.interfaces.length - 1) {
                        interface_construct += ", ";
                    }
                    iface_count++;
                });
                output_string += `// Dll : ${assembly.name}.dll\n// Namespace: ${c.namespace}\n`;
                output_string += `${c.isBlittable ? (c.isEnum ? "internal " : "private ") : ""}${c.isAbstract ? "abstract " : ""}${(c.isEnum ? "enum " : (c.isStruct ? "struct " : (c.isInterface ? "interface " : "class ")))}${c.name}${has_valid_parent ? ` : ${c.parent?.name}` : ""}${iface_count != 0 ? `${has_valid_parent ? ", " : " : "}${interface_construct}` : ""}\n{\n`;
                output_string += "    // Fields\n"
                c.fields.forEach((f) => {
                    output_string += `    ${f.modifier ? f.modifier + " " : ""}${f.isLiteral ? "const " : (f.isStatic ? "static " : "")}${clean_from_sys(f.type.class.name)} ${f.name}${f.isLiteral ? ` = ${f.value.toString().replace("\"\"\"", "\"\\\"\"")}` : ""}; // ${f.offset == 0 ? "0x0" : `0x${f.offset.toString(16)}`}\n`;
                });
                output_string += "\n"
                output_string += "    // Properties (Currently Unavailable)\n\n"
                output_string += "    // Methods\n";
                c.methods.forEach((m) => {
                    let param_construct = "";
                    let param_count = 0;
                    m.parameters.forEach((p) => {
                        param_construct += `${p.type.class.name} ${p.name}`;
                        if (param_count < m.parameters.length - 1) {
                            param_construct += ", ";
                        }
                        param_count++;
                    });
                    output_string += `    // RVA: ${m.virtualAddress.equals(0) ? "0x0" : m.relativeVirtualAddress} VA: ${m.virtualAddress}\n`;
                    output_string += `    ${m.modifier ? m.modifier + " " : ""}${m.isStatic ? "static " : ""}${clean_from_sys(m.returnType.class.name)} ${m.name}(${param_construct}) { }\n`;
                });
                out_arr.push(output_string + "}\n\n");
            })
        });
        console.log("Writing dump output...");
        fs.writeFileSync('./frida_dump.cs', out_arr.join(""));
        console.log("Dump completed! (Saved to Steam game folder)");
    });
}

setTimeout(intermediary, 0);