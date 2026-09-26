use crate::error::Result;

#[cfg(not(windows))]
pub fn run() -> Result<()> {
    Err(crate::error::err(
        "the window needs Windows; pass an updater path instead",
    ))
}

#[cfg(windows)]
pub fn run() -> Result<()> {
    win::run()
}

#[cfg(windows)]
mod win {
    use std::ffi::{OsStr, OsString};
    use std::fs;
    use std::mem::{self, size_of};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::{Path, PathBuf};
    use std::ptr;
    use std::sync::OnceLock;

    use crate::decrypt;
    use crate::error::{err, Result};
    use crate::sha256;

    const WM_DESTROY: u32 = 0x0002;
    const WM_SIZE: u32 = 0x0005;
    const WM_SETFONT: u32 = 0x0030;
    const WM_CLOSE: u32 = 0x0010;
    const WM_GETMINMAXINFO: u32 = 0x0024;
    const WM_COMMAND: u32 = 0x0111;
    const WM_NCDESTROY: u32 = 0x0082;
    const WM_DROPFILES: u32 = 0x0233;
    const WM_DPICHANGED: u32 = 0x02E0;
    const WM_USER: u32 = 0x0400;
    const DM_GETDEFID: u32 = WM_USER;
    const WM_DONE: u32 = 0x8000 + 1;
    const EN_CHANGE: u16 = 0x0300;
    const BN_CLICKED: u16 = 0;
    const DC_HASDEFID: usize = 0x534B;

    const WS_OVERLAPPEDWINDOW: u32 = 0x00CF0000;
    const WS_CLIPCHILDREN: u32 = 0x02000000;
    const WS_CHILD: u32 = 0x40000000;
    const WS_VISIBLE: u32 = 0x10000000;
    const WS_TABSTOP: u32 = 0x00010000;
    const WS_EX_CLIENTEDGE: u32 = 0x00000200;
    const WS_EX_CONTROLPARENT: u32 = 0x00010000;
    const ES_AUTOHSCROLL: u32 = 0x0080;
    const ES_READONLY: u32 = 0x0800;
    const BS_DEFPUSHBUTTON: u32 = 0x0001;
    const SS_LEFT: u32 = 0x0000;
    const SS_LEFTNOWORDWRAP: u32 = 0x000C;
    const SS_NOPREFIX: u32 = 0x0080;
    const SS_ENDELLIPSIS: u32 = 0x4000;
    const SS_PATHELLIPSIS: u32 = 0x8000;

    const CS_HREDRAW: u32 = 0x0002;
    const CS_VREDRAW: u32 = 0x0001;
    const SW_SHOWNORMAL: i32 = 1;
    const SWP_NOZORDER: u32 = 0x0004;
    const SWP_NOACTIVATE: u32 = 0x0010;
    const GWLP_USERDATA: i32 = -21;
    const COLOR_3DFACE: isize = 15;

    const ID_OK: u16 = 1;
    const ID_CANCEL: u16 = 2;
    const ID_UPDATER: u16 = 100;
    const ID_BROWSE: u16 = 101;
    const ID_OUTPUT: u16 = 102;
    const ID_SAVE: u16 = 103;
    const ID_HASH: u16 = 104;

    const OFN_PATHMUSTEXIST: u32 = 0x00000800;
    const OFN_FILEMUSTEXIST: u32 = 0x00001000;
    const OFN_EXPLORER: u32 = 0x00080000;
    const MB_YESNO: u32 = 0x00000004;
    const MB_ICONERROR: u32 = 0x00000010;
    const MB_ICONQUESTION: u32 = 0x00000020;
    const IDYES: i32 = 6;

    const FW_NORMAL: i32 = 400;
    const DEFAULT_CHARSET: u32 = 1;
    const CLEARTYPE_QUALITY: u32 = 5;

    type SetDpiContext = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;
    type GetDpiFn = unsafe extern "system" fn(*mut core::ffi::c_void) -> u32;
    type GetDpiSystemFn = unsafe extern "system" fn() -> u32;
    type WndProc = unsafe extern "system" fn(*mut core::ffi::c_void, u32, usize, isize) -> isize;

    #[repr(C)]
    struct WndClassW {
        style: u32,
        wnd_proc: Option<WndProc>,
        cls_extra: i32,
        wnd_extra: i32,
        instance: *mut core::ffi::c_void,
        icon: *mut core::ffi::c_void,
        cursor: *mut core::ffi::c_void,
        background: *mut core::ffi::c_void,
        menu_name: *const u16,
        class_name: *const u16,
    }

    #[repr(C)]
    struct Msg {
        hwnd: *mut core::ffi::c_void,
        message: u32,
        w_param: usize,
        l_param: isize,
        time: u32,
        x: i32,
        y: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Rect {
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Point {
        x: i32,
        y: i32,
    }

    #[repr(C)]
    struct MinMaxInfo {
        reserved: Point,
        max_size: Point,
        max_position: Point,
        min_track: Point,
        max_track: Point,
    }

    #[repr(C)]
    struct OpenFileNameW {
        struct_size: u32,
        owner: *mut core::ffi::c_void,
        instance: *mut core::ffi::c_void,
        filter: *const u16,
        custom_filter: *mut u16,
        max_custom_filter: u32,
        filter_index: u32,
        file: *mut u16,
        max_file: u32,
        file_title: *mut u16,
        max_file_title: u32,
        initial_dir: *const u16,
        title: *const u16,
        flags: u32,
        file_offset: u16,
        file_extension: u16,
        def_ext: *const u16,
        cust_data: isize,
        hook: *mut core::ffi::c_void,
        template_name: *const u16,
        reserved: *mut core::ffi::c_void,
        reserved_dword: u32,
        flags_ex: u32,
    }

    const _: () = {
        let size = size_of::<OpenFileNameW>();
        let flags = mem::offset_of!(OpenFileNameW, flags);
        let flags_ex = mem::offset_of!(OpenFileNameW, flags_ex);
        assert!(
            (size == 152 && flags == 96 && flags_ex == 148)
                || (size == 88 && flags == 52 && flags_ex == 84)
        );
        let msg = size_of::<Msg>();
        assert!(msg == 48 || msg == 28);
    };

    struct Ui {
        dpi: u32,
        font: *mut core::ffi::c_void,
        ready: bool,
        /// SetWindowText on an edit sends EN_CHANGE before it returns.
        suppress: bool,
        output_edited: bool,
        busy: bool,
        intro: *mut core::ffi::c_void,
        updater_label: *mut core::ffi::c_void,
        updater: *mut core::ffi::c_void,
        browse: *mut core::ffi::c_void,
        output_label: *mut core::ffi::c_void,
        output: *mut core::ffi::c_void,
        save: *mut core::ffi::c_void,
        decrypt: *mut core::ffi::c_void,
        timestamp_label: *mut core::ffi::c_void,
        timestamp: *mut core::ffi::c_void,
        trailer_label: *mut core::ffi::c_void,
        trailer: *mut core::ffi::c_void,
        size_label: *mut core::ffi::c_void,
        size: *mut core::ffi::c_void,
        hash_label: *mut core::ffi::c_void,
        hash: *mut core::ffi::c_void,
        wrote_label: *mut core::ffi::c_void,
        wrote: *mut core::ffi::c_void,
        status: *mut core::ffi::c_void,
    }

    struct Summary {
        timestamp_line: String,
        trailer_line: String,
        size_line: String,
        sha256_hex: String,
        wrote: OsString,
    }

    enum Outcome {
        Ok(Summary),
        Err(String),
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryW(name: *const u16) -> *mut core::ffi::c_void;
        fn GetProcAddress(module: *mut core::ffi::c_void, name: *const u8) -> *mut core::ffi::c_void;
    }

    #[link(name = "user32")]
    extern "system" {
        fn SetProcessDPIAware() -> i32;
        fn RegisterClassW(class: *const WndClassW) -> u16;
        fn CreateWindowExW(
            ex_style: u32,
            class_name: *const u16,
            window_name: *const u16,
            style: u32,
            x: i32,
            y: i32,
            width: i32,
            height: i32,
            parent: *mut core::ffi::c_void,
            menu: *mut core::ffi::c_void,
            instance: *mut core::ffi::c_void,
            param: *mut core::ffi::c_void,
        ) -> *mut core::ffi::c_void;
        fn DefWindowProcW(hwnd: *mut core::ffi::c_void, msg: u32, wparam: usize, lparam: isize) -> isize;
        fn GetMessageW(msg: *mut Msg, hwnd: *mut core::ffi::c_void, min: u32, max: u32) -> i32;
        fn TranslateMessage(msg: *const Msg) -> i32;
        fn DispatchMessageW(msg: *const Msg) -> isize;
        fn IsDialogMessageW(hwnd: *mut core::ffi::c_void, msg: *const Msg) -> i32;
        fn ShowWindow(hwnd: *mut core::ffi::c_void, cmd: i32) -> i32;
        fn UpdateWindow(hwnd: *mut core::ffi::c_void) -> i32;
        fn DestroyWindow(hwnd: *mut core::ffi::c_void) -> i32;
        fn PostQuitMessage(code: i32);
        fn PostMessageW(hwnd: *mut core::ffi::c_void, msg: u32, wparam: usize, lparam: isize) -> i32;
        fn SendMessageW(hwnd: *mut core::ffi::c_void, msg: u32, wparam: usize, lparam: isize) -> isize;
        fn SetWindowLongPtrW(hwnd: *mut core::ffi::c_void, index: i32, value: isize) -> isize;
        fn GetWindowLongPtrW(hwnd: *mut core::ffi::c_void, index: i32) -> isize;
        fn MoveWindow(hwnd: *mut core::ffi::c_void, x: i32, y: i32, w: i32, h: i32, repaint: i32) -> i32;
        fn GetClientRect(hwnd: *mut core::ffi::c_void, rect: *mut Rect) -> i32;
        fn GetSystemMetrics(index: i32) -> i32;
        fn SetWindowPos(
            hwnd: *mut core::ffi::c_void,
            insert_after: *mut core::ffi::c_void,
            x: i32,
            y: i32,
            cx: i32,
            cy: i32,
            flags: u32,
        ) -> i32;
        fn SetWindowTextW(hwnd: *mut core::ffi::c_void, text: *const u16) -> i32;
        fn GetWindowTextW(hwnd: *mut core::ffi::c_void, buf: *mut u16, max: i32) -> i32;
        fn GetWindowTextLengthW(hwnd: *mut core::ffi::c_void) -> i32;
        fn MessageBoxW(
            hwnd: *mut core::ffi::c_void,
            text: *const u16,
            caption: *const u16,
            typ: u32,
        ) -> i32;
        fn EnableWindow(hwnd: *mut core::ffi::c_void, enable: i32) -> i32;
        fn SetFocus(hwnd: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
        fn LoadIconW(instance: *mut core::ffi::c_void, name: *const u16) -> *mut core::ffi::c_void;
        fn LoadCursorW(instance: *mut core::ffi::c_void, name: *const u16) -> *mut core::ffi::c_void;
        fn GetModuleHandleW(name: *const u16) -> *mut core::ffi::c_void;
        fn InvalidateRect(hwnd: *mut core::ffi::c_void, rect: *const Rect, erase: i32) -> i32;
    }

    #[link(name = "gdi32")]
    extern "system" {
        fn CreateFontW(
            height: i32,
            width: i32,
            escapement: i32,
            orientation: i32,
            weight: i32,
            italic: u32,
            underline: u32,
            strike: u32,
            charset: u32,
            out_precision: u32,
            clip_precision: u32,
            quality: u32,
            pitch: u32,
            face: *const u16,
        ) -> *mut core::ffi::c_void;
        fn DeleteObject(obj: *mut core::ffi::c_void) -> i32;
    }

    #[link(name = "comdlg32")]
    extern "system" {
        fn GetOpenFileNameW(ofn: *mut OpenFileNameW) -> i32;
        fn GetSaveFileNameW(ofn: *mut OpenFileNameW) -> i32;
    }

    #[link(name = "shell32")]
    extern "system" {
        fn DragAcceptFiles(hwnd: *mut core::ffi::c_void, accept: i32);
        fn DragQueryFileW(drop: *mut core::ffi::c_void, index: u32, file: *mut u16, chars: u32) -> u32;
        fn DragFinish(drop: *mut core::ffi::c_void);
    }

    pub fn run() -> Result<()> {
        enable_dpi_awareness();
        let instance = unsafe { GetModuleHandleW(ptr::null()) };
        let class_name = wsz("Ft3drDecryptWindow");
        let title = wsz("FT3DR Firmware Decrypt");
        let icon = unsafe { LoadIconW(ptr::null_mut(), 32512 as *const u16) };
        let cursor = unsafe { LoadCursorW(ptr::null_mut(), 32512 as *const u16) };
        let class = WndClassW {
            style: CS_HREDRAW | CS_VREDRAW,
            wnd_proc: Some(wnd_proc),
            cls_extra: 0,
            wnd_extra: 0,
            instance,
            icon,
            cursor,
            background: (COLOR_3DFACE + 1) as *mut core::ffi::c_void,
            menu_name: ptr::null(),
            class_name: class_name.as_ptr(),
        };
        if unsafe { RegisterClassW(&class) } == 0 {
            return Err(err("cannot register the window class"));
        }

        let dpi = system_dpi();
        let width = scale(780, dpi);
        let height = scale(540, dpi);
        let sx = unsafe { GetSystemMetrics(0) };
        let sy = unsafe { GetSystemMetrics(1) };
        let x = ((sx - width) / 2).max(0);
        let y = ((sy - height) / 2).max(0);
        let hwnd = unsafe {
            CreateWindowExW(
                WS_EX_CONTROLPARENT,
                class_name.as_ptr(),
                title.as_ptr(),
                WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                x,
                y,
                width,
                height,
                ptr::null_mut(),
                ptr::null_mut(),
                instance,
                ptr::null_mut(),
            )
        };
        if hwnd.is_null() {
            return Err(err("cannot create the window"));
        }

        let ui = Box::into_raw(Box::new(Ui::new(dpi)));
        unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, ui as isize) };
        if create_controls(hwnd, instance, ui).is_err() {
            unsafe { DestroyWindow(hwnd) };
            return Err(err("cannot create the window"));
        }
        let window_dpi = dpi_for_window(hwnd);
        unsafe { (*ui).dpi = window_dpi };
        apply_font(ui);
        layout(ui, hwnd);
        unsafe {
            (*ui).ready = true;
            DragAcceptFiles(hwnd, 1);
            ShowWindow(hwnd, SW_SHOWNORMAL);
            UpdateWindow(hwnd);
            SetFocus((*ui).updater);
        }

        let mut msg: Msg = unsafe { mem::zeroed() };
        loop {
            let got = unsafe { GetMessageW(&mut msg, ptr::null_mut(), 0, 0) };
            if got == 0 {
                break;
            }
            if got < 0 {
                return Err(err("cannot read window messages"));
            }
            if unsafe { IsDialogMessageW(hwnd, &msg) } == 0 {
                unsafe {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
        }
        Ok(())
    }

    impl Ui {
        fn new(dpi: u32) -> Self {
            Self {
                dpi,
                font: ptr::null_mut(),
                ready: false,
                suppress: false,
                output_edited: false,
                busy: false,
                intro: ptr::null_mut(),
                updater_label: ptr::null_mut(),
                updater: ptr::null_mut(),
                browse: ptr::null_mut(),
                output_label: ptr::null_mut(),
                output: ptr::null_mut(),
                save: ptr::null_mut(),
                decrypt: ptr::null_mut(),
                timestamp_label: ptr::null_mut(),
                timestamp: ptr::null_mut(),
                trailer_label: ptr::null_mut(),
                trailer: ptr::null_mut(),
                size_label: ptr::null_mut(),
                size: ptr::null_mut(),
                hash_label: ptr::null_mut(),
                hash: ptr::null_mut(),
                wrote_label: ptr::null_mut(),
                wrote: ptr::null_mut(),
                status: ptr::null_mut(),
            }
        }
    }

    fn create_controls(
        parent: *mut core::ffi::c_void,
        instance: *mut core::ffi::c_void,
        ui: *mut Ui,
    ) -> Result<()> {
        let edit = wsz("EDIT");
        let button = wsz("BUTTON");
        let label = wsz("STATIC");
        let intro_style = WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX;
        let name_style = WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX;
        let value_style = WS_CHILD | WS_VISIBLE | SS_LEFTNOWORDWRAP | SS_NOPREFIX | SS_ENDELLIPSIS;
        let path_style = WS_CHILD | WS_VISIBLE | SS_LEFTNOWORDWRAP | SS_NOPREFIX | SS_PATHELLIPSIS;
        let edit_style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL;
        let hash_style = edit_style | ES_READONLY;
        let btn_style = WS_CHILD | WS_VISIBLE | WS_TABSTOP;

        unsafe {
            (*ui).intro = child(parent, instance, 0, &label, intro_style, 0, "Decrypts the firmware image stored in an official FT3DR updater.")?;
            (*ui).updater_label = child(parent, instance, 0, &label, name_style, 0, "Updater")?;
            (*ui).updater = child_ex(parent, instance, ID_UPDATER as usize, &edit, edit_style, WS_EX_CLIENTEDGE, "")?;
            (*ui).browse = child(parent, instance, ID_BROWSE as usize, &button, btn_style, 0, "Browse")?;
            (*ui).output_label = child(parent, instance, 0, &label, name_style, 0, "Output")?;
            (*ui).output = child_ex(parent, instance, ID_OUTPUT as usize, &edit, edit_style, WS_EX_CLIENTEDGE, "")?;
            (*ui).save = child(parent, instance, ID_SAVE as usize, &button, btn_style, 0, "Save as")?;
            (*ui).decrypt = child(parent, instance, ID_OK as usize, &button, btn_style | BS_DEFPUSHBUTTON, 0, "Decrypt")?;
            (*ui).timestamp_label = child(parent, instance, 0, &label, name_style, 0, "Timestamp")?;
            (*ui).timestamp = child(parent, instance, 0, &label, value_style, 0, "")?;
            (*ui).trailer_label = child(parent, instance, 0, &label, name_style, 0, "Trailer")?;
            (*ui).trailer = child(parent, instance, 0, &label, value_style, 0, "")?;
            (*ui).size_label = child(parent, instance, 0, &label, name_style, 0, "Size")?;
            (*ui).size = child(parent, instance, 0, &label, value_style, 0, "")?;
            (*ui).hash_label = child(parent, instance, 0, &label, name_style, 0, "SHA-256")?;
            (*ui).hash = child_ex(parent, instance, ID_HASH as usize, &edit, hash_style, WS_EX_CLIENTEDGE, "")?;
            (*ui).wrote_label = child(parent, instance, 0, &label, name_style, 0, "Written")?;
            (*ui).wrote = child(parent, instance, 0, &label, path_style, 0, "")?;
            (*ui).status = child(parent, instance, 0, &label, value_style, 0, "")?;
        }
        Ok(())
    }

    fn child(
        parent: *mut core::ffi::c_void,
        instance: *mut core::ffi::c_void,
        id: usize,
        class_name: &[u16],
        style: u32,
        ex_style: u32,
        text: &str,
    ) -> Result<*mut core::ffi::c_void> {
        child_ex(parent, instance, id, class_name, style, ex_style, text)
    }

    fn child_ex(
        parent: *mut core::ffi::c_void,
        instance: *mut core::ffi::c_void,
        id: usize,
        class_name: &[u16],
        style: u32,
        ex_style: u32,
        text: &str,
    ) -> Result<*mut core::ffi::c_void> {
        let text = wsz(text);
        let hwnd = unsafe {
            CreateWindowExW(
                ex_style,
                class_name.as_ptr(),
                text.as_ptr(),
                style,
                0,
                0,
                0,
                0,
                parent,
                id as *mut core::ffi::c_void,
                instance,
                ptr::null_mut(),
            )
        };
        if hwnd.is_null() {
            Err(err("cannot create the window"))
        } else {
            Ok(hwnd)
        }
    }

    unsafe extern "system" fn wnd_proc(
        hwnd: *mut core::ffi::c_void,
        msg: u32,
        wparam: usize,
        lparam: isize,
    ) -> isize {
        let ui = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut Ui;
        if msg == WM_DONE {
            if lparam != 0 {
                let outcome = Box::from_raw(lparam as *mut Outcome);
                if !ui.is_null() {
                    apply_outcome(hwnd, ui, *outcome);
                }
            }
            return 0;
        }
        if ui.is_null() {
            return DefWindowProcW(hwnd, msg, wparam, lparam);
        }
        match msg {
            DM_GETDEFID => return ((DC_HASDEFID << 16) | ID_OK as usize) as isize,
            WM_COMMAND => {
                on_command(hwnd, ui, wparam);
                return 0;
            }
            WM_SIZE => {
                if (*ui).ready {
                    layout(ui, hwnd);
                }
                return 0;
            }
            WM_GETMINMAXINFO => {
                let info = &mut *(lparam as *mut MinMaxInfo);
                let dpi = if (*ui).dpi == 0 { 96 } else { (*ui).dpi };
                info.min_track.x = scale(640, dpi);
                info.min_track.y = scale(460, dpi);
                return 0;
            }
            WM_DPICHANGED => {
                let dpi = (wparam & 0xFFFF) as u32;
                if dpi != 0 {
                    (*ui).dpi = dpi;
                }
                let suggested = *(lparam as *const Rect);
                apply_font(ui);
                SetWindowPos(
                    hwnd,
                    ptr::null_mut(),
                    suggested.left,
                    suggested.top,
                    suggested.right - suggested.left,
                    suggested.bottom - suggested.top,
                    SWP_NOZORDER | SWP_NOACTIVATE,
                );
                layout(ui, hwnd);
                InvalidateRect(hwnd, ptr::null(), 1);
                return 0;
            }
            WM_DROPFILES => {
                on_drop(ui, lparam as *mut core::ffi::c_void);
                return 0;
            }
            WM_CLOSE => {
                DestroyWindow(hwnd);
                return 0;
            }
            WM_DESTROY => {
                PostQuitMessage(0);
            }
            WM_NCDESTROY => {
                release_ui(hwnd, ui);
            }
            _ => {}
        }
        DefWindowProcW(hwnd, msg, wparam, lparam)
    }

    fn on_command(hwnd: *mut core::ffi::c_void, ui: *mut Ui, wparam: usize) {
        let id = (wparam & 0xFFFF) as u16;
        let code = ((wparam >> 16) & 0xFFFF) as u16;
        if code == EN_CHANGE {
            let suppress = unsafe { (*ui).suppress };
            if suppress {
                return;
            }
            if id == ID_OUTPUT {
                unsafe { (*ui).output_edited = true };
            } else if id == ID_UPDATER && unsafe { !(*ui).output_edited } {
                sync_default_output(ui);
            }
            return;
        }
        if code != BN_CLICKED && id != ID_CANCEL {
            return;
        }
        match id {
            ID_BROWSE => {
                if let Some(path) = pick_file(hwnd, false, edit_os(unsafe { (*ui).updater })) {
                    set_os_text(ui, unsafe { (*ui).updater }, &path);
                    if unsafe { !(*ui).output_edited } {
                        sync_default_output(ui);
                    }
                }
            }
            ID_SAVE => {
                if let Some(path) = pick_file(hwnd, true, edit_os(unsafe { (*ui).output })) {
                    unsafe { (*ui).output_edited = true };
                    set_os_text(ui, unsafe { (*ui).output }, &path);
                }
            }
            ID_OK => on_decrypt(hwnd, ui),
            ID_CANCEL => unsafe {
                DestroyWindow(hwnd);
            },
            _ => {}
        }
    }

    fn on_drop(ui: *mut Ui, drop: *mut core::ffi::c_void) {
        let mut buf = vec![0u16; 32768];
        let n = unsafe { DragQueryFileW(drop, 0, buf.as_mut_ptr(), buf.len() as u32) };
        unsafe { DragFinish(drop) };
        if n == 0 {
            return;
        }
        let end = (n as usize).min(buf.len());
        let path = OsString::from_wide(&buf[..end]);
        set_os_text(ui, unsafe { (*ui).updater }, &path);
        if unsafe { !(*ui).output_edited } {
            sync_default_output(ui);
        }
    }

    fn on_decrypt(hwnd: *mut core::ffi::c_void, ui: *mut Ui) {
        if unsafe { (*ui).busy } {
            return;
        }
        let updater = edit_os(unsafe { (*ui).updater });
        let output = edit_os(unsafe { (*ui).output });
        if updater.is_empty() {
            set_status(ui, "Choose an updater executable.");
            return;
        }
        if output.is_empty() {
            set_status(ui, "Choose an output file.");
            return;
        }
        let out_path = PathBuf::from(output);
        if out_path.exists() {
            let answer = message_box(hwnd, "Replace the existing file?", MB_YESNO | MB_ICONQUESTION);
            if answer != IDYES {
                set_status(ui, "Left the existing file in place.");
                return;
            }
        }
        let button = unsafe { (*ui).decrypt };
        unsafe { (*ui).busy = true };
        unsafe { EnableWindow(button, 0) };
        set_status(ui, "Decrypting\u{2026}");
        let hwnd_bits = hwnd as usize;
        let updater_path = PathBuf::from(updater);
        std::thread::spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                decrypt_to_summary(updater_path, out_path)
            }));
            let outcome = match outcome {
                Ok(Ok(summary)) => Outcome::Ok(summary),
                Ok(Err(e)) => Outcome::Err(e.to_string()),
                Err(_) => Outcome::Err("decrypt failed".to_string()),
            };
            post_outcome(hwnd_bits as *mut core::ffi::c_void, outcome);
        });
    }

    fn decrypt_to_summary(updater: PathBuf, output: PathBuf) -> Result<Summary> {
        let pe_bytes = fs::read(&updater)
            .map_err(|e| err(format!("cannot read {}: {e}", updater.display())))?;
        let mut report = decrypt::decrypt_pe(&pe_bytes)?;
        let bytes = report.plaintext.len();
        let digest = sha256::to_hex(&sha256::sha256(&report.plaintext));
        fs::write(&output, &report.plaintext)
            .map_err(|e| err(format!("cannot write {}: {e}", output.display())))?;
        drop(mem::take(&mut report.plaintext));
        let trailer_line = if report.trailer.is_empty() {
            "\u{2014}".to_string()
        } else {
            report.trailer.join(", ")
        };
        Ok(Summary {
            timestamp_line: format!("{} ({} UTC)", report.timestamp, report.timestamp_utc),
            trailer_line,
            size_line: format!("{bytes} bytes"),
            sha256_hex: digest,
            wrote: output.into_os_string(),
        })
    }

    /// The worker allocates the box. The window proc frees it. If the post fails, free it here.
    fn post_outcome(hwnd: *mut core::ffi::c_void, outcome: Outcome) {
        let raw = Box::into_raw(Box::new(outcome));
        let posted = unsafe { PostMessageW(hwnd, WM_DONE, 0, raw as isize) };
        if posted == 0 {
            unsafe { drop(Box::from_raw(raw)) };
        }
    }

    fn apply_outcome(hwnd: *mut core::ffi::c_void, ui: *mut Ui, outcome: Outcome) {
        let button = unsafe { (*ui).decrypt };
        unsafe { (*ui).busy = false };
        unsafe { EnableWindow(button, 1) };
        match outcome {
            Outcome::Ok(summary) => {
                set_text(unsafe { (*ui).timestamp }, &summary.timestamp_line);
                set_text(unsafe { (*ui).trailer }, &summary.trailer_line);
                set_text(unsafe { (*ui).size }, &summary.size_line);
                set_text(unsafe { (*ui).hash }, &summary.sha256_hex);
                set_os_text(ui, unsafe { (*ui).wrote }, &summary.wrote);
                set_status(ui, "Done.");
            }
            Outcome::Err(text) => {
                clear_results(ui);
                set_status(ui, &text);
                message_box(hwnd, &text, MB_ICONERROR);
            }
        }
    }

    fn clear_results(ui: *mut Ui) {
        set_text(unsafe { (*ui).timestamp }, "");
        set_text(unsafe { (*ui).trailer }, "");
        set_text(unsafe { (*ui).size }, "");
        set_text(unsafe { (*ui).hash }, "");
        set_text(unsafe { (*ui).wrote }, "");
    }

    fn sync_default_output(ui: *mut Ui) {
        let updater = edit_os(unsafe { (*ui).updater });
        let output = unsafe { (*ui).output };
        if let Ok(path) = decrypt::default_output(Path::new(&updater)) {
            set_os_text(ui, output, path.as_os_str());
        }
    }

    fn set_os_text(ui: *mut Ui, edit: *mut core::ffi::c_void, text: &OsStr) {
        let wide = wide_os(text);
        let prev = unsafe { (*ui).suppress };
        unsafe { (*ui).suppress = true };
        unsafe { SetWindowTextW(edit, wide.as_ptr()) };
        unsafe { (*ui).suppress = prev };
    }

    fn set_text(hwnd: *mut core::ffi::c_void, text: &str) {
        let wide = wsz(text);
        unsafe { SetWindowTextW(hwnd, wide.as_ptr()) };
    }

    fn set_status(ui: *mut Ui, text: &str) {
        let status = unsafe { (*ui).status };
        set_text(status, text);
    }

    fn edit_os(hwnd: *mut core::ffi::c_void) -> OsString {
        let n = unsafe { GetWindowTextLengthW(hwnd) };
        if n <= 0 {
            return OsString::new();
        }
        let mut buf = vec![0u16; n as usize + 1];
        let got = unsafe { GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32) };
        if got <= 0 {
            return OsString::new();
        }
        OsString::from_wide(&buf[..got as usize])
    }

    fn message_box(owner: *mut core::ffi::c_void, text: &str, flags: u32) -> i32 {
        let text = wsz(text);
        let title = wsz("FT3DR Firmware Decrypt");
        unsafe { MessageBoxW(owner, text.as_ptr(), title.as_ptr(), flags) }
    }

    fn pick_file(owner: *mut core::ffi::c_void, save: bool, current: OsString) -> Option<OsString> {
        let filter = if save {
            dialog_filter(&[
                ("Firmware image (*.bin)", "*.bin"),
                ("All files (*.*)", "*.*"),
            ])
        } else {
            dialog_filter(&[
                ("Updater executable (*.exe)", "*.exe"),
                ("All files (*.*)", "*.*"),
            ])
        };
        let title = wsz(if save {
            "Save firmware image"
        } else {
            "Open FT3DR updater"
        });
        let def_ext = wsz("bin");
        let mut file = vec![0u16; 32768];
        prefill(&mut file, current.as_os_str());
        let mut ofn = OpenFileNameW {
            struct_size: size_of::<OpenFileNameW>() as u32,
            owner,
            instance: ptr::null_mut(),
            filter: filter.as_ptr(),
            custom_filter: ptr::null_mut(),
            max_custom_filter: 0,
            filter_index: 1,
            file: file.as_mut_ptr(),
            max_file: file.len() as u32,
            file_title: ptr::null_mut(),
            max_file_title: 0,
            initial_dir: ptr::null(),
            title: title.as_ptr(),
            flags: if save {
                OFN_PATHMUSTEXIST | OFN_EXPLORER
            } else {
                OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER
            },
            file_offset: 0,
            file_extension: 0,
            def_ext: if save { def_ext.as_ptr() } else { ptr::null() },
            cust_data: 0,
            hook: ptr::null_mut(),
            template_name: ptr::null(),
            reserved: ptr::null_mut(),
            reserved_dword: 0,
            flags_ex: 0,
        };
        let ok = unsafe {
            if save {
                GetSaveFileNameW(&mut ofn)
            } else {
                GetOpenFileNameW(&mut ofn)
            }
        };
        if ok == 0 {
            return None;
        }
        let end = file.iter().position(|&c| c == 0).unwrap_or(file.len());
        if end == 0 {
            None
        } else {
            Some(OsString::from_wide(&file[..end]))
        }
    }

    fn prefill(buf: &mut [u16], text: &OsStr) {
        let wide: Vec<u16> = text.encode_wide().collect();
        if wide.len() + 1 > buf.len() {
            return;
        }
        buf[..wide.len()].copy_from_slice(&wide);
        buf[wide.len()] = 0;
    }

    fn dialog_filter(pairs: &[(&str, &str)]) -> Vec<u16> {
        let mut out = Vec::new();
        for (label, pattern) in pairs {
            out.extend(label.encode_utf16());
            out.push(0);
            out.extend(pattern.encode_utf16());
            out.push(0);
        }
        out.push(0);
        out
    }

    fn layout(ui: *mut Ui, hwnd: *mut core::ffi::c_void) {
        let mut rc = Rect {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        unsafe { GetClientRect(hwnd, &mut rc) };
        let dpi = unsafe { (*ui).dpi };
        let width = rc.right - rc.left;
        let height = rc.bottom - rc.top;
        if width <= 0 || height <= 0 {
            return;
        }
        let m = scale(16, dpi);
        let gap = scale(8, dpi);
        let label_h = scale(18, dpi);
        let edit_h = scale(24, dpi);
        let btn_w = scale(96, dpi);
        let row = scale(10, dpi);
        let content_w = (width - m * 2).max(1);
        let edit_w = (content_w - btn_w - gap).max(1);
        let label_w = scale(92, dpi);
        let value_x = m + label_w + gap;
        let value_w = (content_w - label_w - gap).max(1);

        let intro_h = scale(36, dpi);
        let mut y = m;
        place(unsafe { (*ui).intro }, m, y, content_w, intro_h);
        y += intro_h + row;
        place(unsafe { (*ui).updater_label }, m, y, content_w, label_h);
        y += label_h + scale(2, dpi);
        place(unsafe { (*ui).updater }, m, y, edit_w, edit_h);
        place(unsafe { (*ui).browse }, m + edit_w + gap, y, btn_w, edit_h);
        y += edit_h + row;
        place(unsafe { (*ui).output_label }, m, y, content_w, label_h);
        y += label_h + scale(2, dpi);
        place(unsafe { (*ui).output }, m, y, edit_w, edit_h);
        place(unsafe { (*ui).save }, m + edit_w + gap, y, btn_w, edit_h);
        y += edit_h + row;
        place(unsafe { (*ui).decrypt }, m, y, scale(110, dpi), edit_h);
        y += edit_h + scale(16, dpi);

        let row_at = |label, value, y: &mut i32| {
            place(label, m, *y, label_w, label_h);
            place(value, value_x, *y, value_w, label_h);
            *y += label_h + scale(4, dpi);
        };
        row_at(unsafe { (*ui).timestamp_label }, unsafe { (*ui).timestamp }, &mut y);
        row_at(unsafe { (*ui).trailer_label }, unsafe { (*ui).trailer }, &mut y);
        row_at(unsafe { (*ui).size_label }, unsafe { (*ui).size }, &mut y);
        y += scale(4, dpi);
        place(unsafe { (*ui).hash_label }, m, y, content_w, label_h);
        y += label_h + scale(2, dpi);
        place(unsafe { (*ui).hash }, m, y, content_w, edit_h);
        y += edit_h + row;
        row_at(unsafe { (*ui).wrote_label }, unsafe { (*ui).wrote }, &mut y);

        let status_h = label_h;
        let status_y = (height - m - status_h).max(y);
        place(unsafe { (*ui).status }, m, status_y, content_w, status_h);
    }

    fn place(hwnd: *mut core::ffi::c_void, x: i32, y: i32, w: i32, h: i32) {
        if !hwnd.is_null() {
            unsafe { MoveWindow(hwnd, x, y, w.max(1), h.max(1), 1) };
        }
    }

    fn apply_font(ui: *mut Ui) {
        let dpi = unsafe { (*ui).dpi };
        let font = create_ui_font(dpi);
        let old = unsafe { (*ui).font };
        unsafe { (*ui).font = font };
        if !font.is_null() {
            for hwnd in control_handles(ui) {
                if !hwnd.is_null() {
                    unsafe { SendMessageW(hwnd, WM_SETFONT, font as usize, 1) };
                }
            }
        }
        if !old.is_null() {
            unsafe { DeleteObject(old) };
        }
    }

    fn control_handles(ui: *mut Ui) -> [*mut core::ffi::c_void; 19] {
        unsafe {
            [
                (*ui).intro,
                (*ui).updater_label,
                (*ui).updater,
                (*ui).browse,
                (*ui).output_label,
                (*ui).output,
                (*ui).save,
                (*ui).decrypt,
                (*ui).timestamp_label,
                (*ui).timestamp,
                (*ui).trailer_label,
                (*ui).trailer,
                (*ui).size_label,
                (*ui).size,
                (*ui).hash_label,
                (*ui).hash,
                (*ui).wrote_label,
                (*ui).wrote,
                (*ui).status,
            ]
        }
    }

    fn create_ui_font(dpi: u32) -> *mut core::ffi::c_void {
        let face = wsz("Segoe UI");
        let height = -scale_mul(9, dpi as i32, 72);
        unsafe {
            CreateFontW(
                height,
                0,
                0,
                0,
                FW_NORMAL,
                0,
                0,
                0,
                DEFAULT_CHARSET,
                0,
                0,
                CLEARTYPE_QUALITY,
                0,
                face.as_ptr(),
            )
        }
    }

    fn release_ui(hwnd: *mut core::ffi::c_void, ui: *mut Ui) {
        unsafe {
            let font = (*ui).font;
            (*ui).font = ptr::null_mut();
            if !font.is_null() {
                DeleteObject(font);
            }
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            drop(Box::from_raw(ui));
        }
    }

    fn scale(px: i32, dpi: u32) -> i32 {
        let dpi = if dpi == 0 { 96 } else { dpi as i32 };
        scale_mul(px, dpi, 96)
    }

    fn scale_mul(a: i32, b: i32, c: i32) -> i32 {
        if c == 0 {
            return a;
        }
        (a as i64 * b as i64 / c as i64) as i32
    }

    fn wsz(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn wide_os(text: &OsStr) -> Vec<u16> {
        text.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn enable_dpi_awareness() {
        unsafe {
            let user32 = load_user32();
            if user32.is_null() {
                return;
            }
            let set_ctx = GetProcAddress(user32, b"SetProcessDpiAwarenessContext\0".as_ptr());
            if set_ctx.is_null() {
                SetProcessDPIAware();
                return;
            }
            let f: SetDpiContext = mem::transmute(set_ctx);
            // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
            f(-4isize as *mut core::ffi::c_void);
        }
    }

    fn system_dpi() -> u32 {
        static FN: OnceLock<usize> = OnceLock::new();
        let addr = FN.get_or_init(|| resolve_user32(b"GetDpiForSystem\0"));
        if *addr == 0 {
            return 96;
        }
        let f: GetDpiSystemFn = unsafe { mem::transmute(*addr) };
        let dpi = unsafe { f() };
        if dpi == 0 { 96 } else { dpi }
    }

    fn dpi_for_window(hwnd: *mut core::ffi::c_void) -> u32 {
        static FN: OnceLock<usize> = OnceLock::new();
        let addr = FN.get_or_init(|| resolve_user32(b"GetDpiForWindow\0"));
        if *addr == 0 {
            return system_dpi();
        }
        let f: GetDpiFn = unsafe { mem::transmute(*addr) };
        let dpi = unsafe { f(hwnd) };
        if dpi == 0 { 96 } else { dpi }
    }

    fn resolve_user32(name: &[u8]) -> usize {
        unsafe {
            let user32 = load_user32();
            if user32.is_null() {
                return 0;
            }
            GetProcAddress(user32, name.as_ptr()) as usize
        }
    }

    fn load_user32() -> *mut core::ffi::c_void {
        static MOD: OnceLock<usize> = OnceLock::new();
        let addr = MOD.get_or_init(|| {
            let name = wsz("user32.dll");
            unsafe { LoadLibraryW(name.as_ptr()) as usize }
        });
        *addr as *mut core::ffi::c_void
    }
}
