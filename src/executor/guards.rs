#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

#[cfg(unix)]
use std::os::unix::io::RawFd;


#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_IO_PENDING, ERROR_OPERATION_ABORTED, FALSE, HANDLE,
    INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0,
};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_CHAR, GetFileType,
    OPEN_EXISTING, ReadFile,
};
#[cfg(windows)]
use windows_sys::Win32::System::Console::{
    ENABLE_ECHO_INPUT, ENABLE_EXTENDED_FLAGS, ENABLE_LINE_INPUT, GetConsoleMode,
    GetStdHandle, SetConsoleMode, STD_INPUT_HANDLE,
};
#[cfg(windows)]
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    CreateEventW, SetEvent, WaitForMultipleObjects, INFINITE,
};

#[cfg(windows)]
pub(super) struct ConsoleInputHandle {
    handle: HANDLE,
}

#[cfg(windows)]
impl ConsoleInputHandle {
    pub(super) fn open() -> std::io::Result<Self> {
        let name: Vec<u16> = OsStr::new("CONIN$")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                0,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(Self { handle })
        }
    }

    pub(super) fn handle(&self) -> HANDLE {
        self.handle
    }
}

#[cfg(windows)]
impl Drop for ConsoleInputHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

#[cfg(windows)]
pub(super) struct ConsoleModeGuard {
    handle: HANDLE,
    original_mode: u32,
    modified: bool,
}

#[cfg(windows)]
impl ConsoleModeGuard {
    pub(super) fn new(handle: HANDLE) -> std::io::Result<Self> {
        Self::new_with_options(handle, false, false)
    }

    pub(super) fn new_for_pty_input(handle: HANDLE) -> std::io::Result<Self> {
        Self::new_with_options(handle, true, true)
    }

    fn new_with_options(
        handle: HANDLE,
        disable_echo: bool,
        disable_line_input: bool,
    ) -> std::io::Result<Self> {
        let mut original = 0u32;
        if unsafe { GetConsoleMode(handle, &mut original) } == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut new_mode = original | ENABLE_EXTENDED_FLAGS;
        let mut modified = new_mode != original;

        if disable_line_input && (new_mode & ENABLE_LINE_INPUT) != 0 {
            new_mode &= !ENABLE_LINE_INPUT;
            modified = true;
        }

        if disable_echo && (new_mode & ENABLE_ECHO_INPUT) != 0 {
            new_mode &= !ENABLE_ECHO_INPUT;
            modified = true;
        }

        if modified {
            if unsafe { SetConsoleMode(handle, new_mode) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Self {
                handle,
                original_mode: original,
                modified: true,
            })
        } else {
            Ok(Self {
                handle,
                original_mode: original,
                modified: false,
            })
        }
    }
}

#[cfg(windows)]
impl Drop for ConsoleModeGuard {
    fn drop(&mut self) {
        if self.modified {
            unsafe {
                SetConsoleMode(self.handle, self.original_mode);
            }
        }
    }
}

#[cfg(windows)]
pub(super) struct WindowsEvent {
    handle: HANDLE,
}

#[cfg(windows)]
impl WindowsEvent {
    pub(super) fn new(manual_reset: bool, initial_state: bool) -> std::io::Result<Self> {
        let handle = unsafe {
            CreateEventW(
                std::ptr::null_mut(),
                if manual_reset { 1 } else { 0 },
                if initial_state { 1 } else { 0 },
                std::ptr::null(),
            )
        };
        if handle == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(Self { handle })
        }
    }

    pub(super) fn set(&self) -> std::io::Result<()> {
        if unsafe { SetEvent(self.handle) } == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub(super) fn handle(&self) -> HANDLE {
        self.handle
    }
}

#[cfg(windows)]
impl Drop for WindowsEvent {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

#[cfg(unix)]
pub(super) struct FdFlagGuard {
    fd: RawFd,
    original: libc::c_int,
}

#[cfg(unix)]
impl FdFlagGuard {
    pub(super) fn new(fd: RawFd) -> std::io::Result<Self> {
        let original = get_fd_flags(fd)?;
        set_fd_flags(fd, original | libc::O_NONBLOCK)?;
        Ok(Self { fd, original })
    }
}

#[cfg(unix)]
impl Drop for FdFlagGuard {
    fn drop(&mut self) {
        let _ = set_fd_flags(self.fd, self.original);
    }
}

#[cfg(unix)]
pub(super) struct UnixTerminalModeGuard {
    fd: RawFd,
    original: libc::termios,
    modified: bool,
}

#[cfg(unix)]
impl UnixTerminalModeGuard {
    pub(super) fn new_for_pty_input(fd: RawFd) -> std::io::Result<Self> {
        let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut mode = original;
        mode.c_lflag &= !(libc::ECHO | libc::ICANON);
        mode.c_cc[libc::VMIN] = 1;
        mode.c_cc[libc::VTIME] = 0;

        let modified = mode.c_lflag != original.c_lflag
            || mode.c_cc[libc::VMIN] != original.c_cc[libc::VMIN]
            || mode.c_cc[libc::VTIME] != original.c_cc[libc::VTIME];

        if modified && unsafe { libc::tcsetattr(fd, libc::TCSANOW, &mode) } != 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self {
            fd,
            original,
            modified,
        })
    }
}

#[cfg(unix)]
impl Drop for UnixTerminalModeGuard {
    fn drop(&mut self) {
        if self.modified {
            let _ = unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original) };
        }
    }
}

#[cfg(unix)]
pub(super) fn get_fd_flags(fd: RawFd) -> std::io::Result<libc::c_int> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(flags)
    }
}

#[cfg(unix)]
pub(super) fn set_fd_flags(fd: RawFd, flags: libc::c_int) -> std::io::Result<()> {
    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags) };
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
pub(super) fn stdin_is_console() -> Result<bool, anyhow::Error> {
    use anyhow::Context as _;

    unsafe {
        let handle = GetStdHandle(STD_INPUT_HANDLE);
        if handle == INVALID_HANDLE_VALUE {
            let err = std::io::Error::last_os_error();
            return Err(err).context("Failed to acquire standard input handle");
        }
        if handle == 0 {
            return Ok(false);
        }
        if GetFileType(handle) != FILE_TYPE_CHAR {
            return Ok(false);
        }
        let mut mode = 0u32;
        if GetConsoleMode(handle, &mut mode) == 0 {
            return Ok(false);
        }
        Ok(true)
    }
}

#[cfg(unix)]
pub(super) fn stdin_is_tty() -> bool {
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
}

#[cfg(windows)]
pub(super) fn console_io_read_loop(
    console_handle: HANDLE,
    shutdown: &WindowsEvent,
    mut write_chunk: impl FnMut(&[u8]) -> anyhow::Result<bool>,
) -> anyhow::Result<()> {
    use anyhow::Context as _;

    let overlapped_event =
        WindowsEvent::new(false, false).context("Failed to create overlapped read event")?;
    let mut buffer = [0u8; 8192];

    loop {
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.hEvent = overlapped_event.handle();

        let read_result = unsafe {
            ReadFile(
                console_handle,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                std::ptr::null_mut(),
                &mut overlapped,
            )
        };

        if read_result == 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(code) if code == ERROR_IO_PENDING as i32 => {}
                Some(code) if code == ERROR_OPERATION_ABORTED as i32 => continue,
                _ => {
                    return Err(err).context("Failed to initiate console read");
                }
            }
        }

        let handles = [overlapped_event.handle(), shutdown.handle()];
        let wait_result = unsafe {
            WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), FALSE, INFINITE)
        };

        if wait_result == WAIT_OBJECT_0 {
            let mut bytes_read: u32 = 0;
            let completed = unsafe {
                GetOverlappedResult(console_handle, &overlapped, &mut bytes_read, FALSE)
            };
            if completed == 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(ERROR_OPERATION_ABORTED as i32) {
                    continue;
                }
                return Err(err).context("Failed to complete console read");
            }

            if bytes_read == 0 {
                break;
            }

            let chunk = &buffer[..bytes_read as usize];
            let should_break = write_chunk(chunk)
                .context("Failed to process console input chunk")?;
            if should_break {
                break;
            }
        } else if wait_result == WAIT_OBJECT_0 + 1 {
            unsafe {
                CancelIoEx(console_handle, &overlapped);
            }
            let mut _bytes: u32 = 0;
            unsafe {
                GetOverlappedResult(console_handle, &overlapped, &mut _bytes, FALSE);
            }
            break;
        } else if wait_result == WAIT_FAILED {
            let err = std::io::Error::last_os_error();
            return Err(err).context("Waiting on console read failed");
        } else {
            continue;
        }
    }

    Ok(())
}
