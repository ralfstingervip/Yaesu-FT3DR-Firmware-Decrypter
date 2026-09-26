use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0" xmlns:asmv3="urn:schemas-microsoft-com:asm.v3">
  <assemblyIdentity type="win32" name="yaesu-ft3dr-decrypt" version="1.1.0.0"/>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
          type="win32"
          name="Microsoft.Windows.Common-Controls"
          version="6.0.0.0"
          processorArchitecture="*"
          publicKeyToken="6595b64144ccf1df"
          language="*"/>
    </dependentAssembly>
  </dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <asmv3:application>
    <asmv3:windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </asmv3:windowsSettings>
  </asmv3:application>
</assembly>
"#;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os != "windows" {
        return;
    }
    let env_name = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap_or_default());
    if out_dir.as_os_str().is_empty() {
        return;
    }
    let manifest = out_dir.join("yaesu-ft3dr-decrypt.manifest");
    if fs::write(&manifest, MANIFEST).is_err() {
        return;
    }
    if env_name == "msvc" {
        let path = manifest.display().to_string();
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:\"{path}\"");
        return;
    }
    if env_name == "gnu" {
        let _ = embed_gnu_manifest(&out_dir, &manifest);
    }
}

/// The mingw driver links `default-manifest.o` beside a user manifest, and ld then
/// refuses to merge the two. Drop that input so the embedded manifest is the only one.
fn specs_without_default_manifest() -> Option<PathBuf> {
    let output = Command::new("gcc").arg("-dumpspecs").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let marker = "%{!shared:%:if-exists(default-manifest.o%s)}";
    let start = text.find("*endfile:")?;
    let rest = &text[start + "*endfile:".len()..];
    let end = rest.find("\n*").unwrap_or(rest.len());
    let body = &rest[..end];
    if !body.contains(marker) {
        return None;
    }
    let body = body.replace(marker, "");
    let dir = PathBuf::from(env::var("OUT_DIR").ok()?);
    let path = dir.join("no-default-manifest.specs");
    fs::write(&path, format!("*endfile:{body}")).ok()?;
    Some(path)
}

fn embed_gnu_manifest(out_dir: &std::path::Path, _manifest: &std::path::Path) -> std::io::Result<()> {
    let rc_path = out_dir.join("manifest.rc");
    let obj_path = out_dir.join("manifest.o");
    fs::write(&rc_path, "1 24 \"yaesu-ft3dr-decrypt.manifest\"\n")?;
    let status = Command::new("windres")
        .current_dir(out_dir)
        .args([
            "-F",
            "pe-x86-64",
            "-O",
            "coff",
            "-i",
            "manifest.rc",
            "-o",
            "manifest.o",
        ])
        .status();
    match status {
        Ok(code) if code.success() => {
            println!("cargo:rustc-link-arg={}", obj_path.display());
            if let Some(specs) = specs_without_default_manifest() {
                println!("cargo:rustc-link-arg=-specs={}", specs.display());
            }
            Ok(())
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "windres failed",
        )),
    }
}
