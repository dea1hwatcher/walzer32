use std::collections::HashMap;
use walzer32_core::GuestAddr;
use walzer32_elf::LoadedLibrary;

/// Parsed metadata for an exported 32-bit guest JNI method
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JniMethodInfo {
    /// Raw exported symbol name in ELF dynamic symbol table (e.g. "Java_com_foo_Bar_baz")
    pub symbol: String,
    /// Slash-delimited Java class path (e.g. "com/foo/Bar")
    pub class_name: String,
    /// Java method name (e.g. "baz")
    pub method_name: String,
    /// Optional overloaded method signature if present in mangled name
    pub signature: Option<String>,
    /// Virtual guest address of the native implementation
    pub fn_ptr: GuestAddr,
}

/// Registry storing and indexing discovered guest JNI exports across loaded libraries
#[derive(Debug, Default, Clone)]
pub struct JniMethodRegistry {
    pub methods_by_symbol: HashMap<String, JniMethodInfo>,
    pub methods_by_class_method: HashMap<(String, String), JniMethodInfo>,
}

impl JniMethodRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Discovers and indexes all JNI methods exported by a loaded 32-bit library
    pub fn register_library(&mut self, lib: &LoadedLibrary) -> Vec<JniMethodInfo> {
        let mut discovered = Vec::new();

        for (sym, &addr) in &lib.symbols {
            if sym.starts_with("Java_") {
                if let Some(info) = parse_jni_export(sym, addr) {
                    self.methods_by_symbol.insert(sym.clone(), info.clone());
                    self.methods_by_class_method.insert(
                        (info.class_name.clone(), info.method_name.clone()),
                        info.clone(),
                    );
                    discovered.push(info);
                }
            }
        }

        discovered
    }

    /// Finds a registered JNI method by its raw mangled symbol name
    pub fn find_by_symbol(&self, symbol: &str) -> Option<&JniMethodInfo> {
        self.methods_by_symbol.get(symbol)
    }

    /// Finds a registered JNI method by class name and method name
    pub fn find_by_class_and_method(&self, class_name: &str, method_name: &str) -> Option<&JniMethodInfo> {
        self.methods_by_class_method.get(&(class_name.to_string(), method_name.to_string()))
    }

    /// Total count of registered JNI methods
    pub fn method_count(&self) -> usize {
        self.methods_by_symbol.len()
    }
}

/// Parses an ELF exported symbol into structured JNI method information according to Oracle JNI spec
pub fn parse_jni_export(symbol: &str, fn_ptr: GuestAddr) -> Option<JniMethodInfo> {
    if !symbol.starts_with("Java_") {
        return None;
    }

    let remainder = &symbol["Java_".len()..];

    // Check for overloaded signature separator "__"
    let (body, signature) = if let Some(sig_idx) = remainder.find("__") {
        let body = &remainder[..sig_idx];
        let sig_part = &remainder[sig_idx + 2..];
        (body, Some(unescape_jni_mangling(sig_part)))
    } else {
        (remainder, None)
    };

    // Find last unescaped underscore separating class name and method name
    let unescaped_body = unescape_jni_mangling(body);
    let last_slash_or_sep = unescaped_body.rfind('/')?;

    let class_name = unescaped_body[..last_slash_or_sep].to_string();
    let method_name = unescaped_body[last_slash_or_sep + 1..].to_string();

    Some(JniMethodInfo {
        symbol: symbol.to_string(),
        class_name,
        method_name,
        signature,
        fn_ptr,
    })
}

/// Unescapes JNI mangling escapes according to Java Native Interface specification:
///   _1 -> _
///   _2 -> ;
///   _3 -> [
///   _  -> /
fn unescape_jni_mangling(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '_' {
            match chars.peek() {
                Some('1') => {
                    chars.next();
                    result.push('_');
                }
                Some('2') => {
                    chars.next();
                    result.push(';');
                }
                Some('3') => {
                    chars.next();
                    result.push('[');
                }
                _ => {
                    result.push('/');
                }
            }
        } else {
            result.push(c);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_jni_export_standard() {
        let sym = "Java_com_noodlecake_noodlenews_NoodlecakeGameActivity_getPlatform";
        let info = parse_jni_export(sym, GuestAddr::new(0x7002_0000)).unwrap();
        assert_eq!(info.class_name, "com/noodlecake/noodlenews/NoodlecakeGameActivity");
        assert_eq!(info.method_name, "getPlatform");
        assert_eq!(info.signature, None);
        assert_eq!(info.fn_ptr, GuestAddr::new(0x7002_0000));
    }

    #[test]
    fn test_parse_jni_export_with_escaped_underscore() {
        let sym = "Java_org_cocos2dx_lib_Cocos2dxHelper_nativeSet_1EditTextDialogResult";
        let info = parse_jni_export(sym, GuestAddr::new(0x7003_0000)).unwrap();
        assert_eq!(info.class_name, "org/cocos2dx/lib/Cocos2dxHelper");
        assert_eq!(info.method_name, "nativeSet_EditTextDialogResult");
    }

    #[test]
    fn test_parse_jni_export_with_signature() {
        let sym = "Java_com_test_App_render__II";
        let info = parse_jni_export(sym, GuestAddr::new(0x7004_0000)).unwrap();
        assert_eq!(info.class_name, "com/test/App");
        assert_eq!(info.method_name, "render");
        assert_eq!(info.signature.as_deref(), Some("II"));
    }
}
