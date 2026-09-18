//! 将文本写入系统剪贴板。仅在 Windows 上实现；其它平台返回明确错误。

/// 把 UTF-8 文本复制到系统剪贴板（Windows 使用 `CF_UNICODETEXT`）。
#[cfg(windows)]
pub fn copy_to_clipboard(text: &str) -> Result<(), String> {
    use std::ptr;
    use windows_sys::Win32::Foundation::GlobalFree;
    use windows_sys::Win32::System::Console::GetConsoleWindow;
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
    };
    use windows_sys::Win32::System::Memory::{
        GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE,
    };

    // windows-sys 把 CF_UNICODETEXT 常量放在 Win32::System::Ole，这里直接使用其值。
    const CF_UNICODETEXT: u32 = 13;

    let wide = text
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let byte_len = wide.len() * size_of::<u16>();

    unsafe {
        let hglobal = GlobalAlloc(GMEM_MOVEABLE, byte_len);
        if hglobal.is_null() {
            return Err("分配剪贴板内存失败".into());
        }
        let locked = GlobalLock(hglobal);
        if locked.is_null() {
            GlobalFree(hglobal);
            return Err("锁定剪贴板内存失败".into());
        }
        ptr::copy_nonoverlapping(wide.as_ptr() as *const u8, locked as *mut u8, byte_len);
        GlobalUnlock(hglobal);

        let owner = GetConsoleWindow();
        if owner.is_null() {
            GlobalFree(hglobal);
            return Err("无法获取当前终端窗口，不能打开剪贴板".into());
        }
        let mut opened = false;
        for _ in 0..5 {
            if OpenClipboard(owner) != 0 {
                opened = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if !opened {
            GlobalFree(hglobal);
            return Err("无法打开剪贴板（可能被其它程序占用）".into());
        }
        if EmptyClipboard() == 0 {
            CloseClipboard();
            GlobalFree(hglobal);
            return Err("无法清空剪贴板".into());
        }
        if SetClipboardData(CF_UNICODETEXT, hglobal).is_null() {
            CloseClipboard();
            GlobalFree(hglobal);
            return Err("写入剪贴板失败".into());
        }
        // 成功：剪贴板接管该内存句柄，不得再释放。
        CloseClipboard();
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn copy_to_clipboard(_text: &str) -> Result<(), String> {
    Err("当前平台暂不支持一键复制，请手动复制预览内容".into())
}
