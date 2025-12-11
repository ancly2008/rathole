// src/helper.rs

// 🌟 修改: 引入 libc 和 socket2 的 SetSockOpt trait
use anyhow::{anyhow, Context, Result};
use async_http_proxy::{http_connect_tokio, http_connect_tokio_with_basic_auth};
use backoff::{backoff::Backoff, Notify};
// 🌟 仅保留 SockRef 和 TcpKeepalive，并引入 SetSockOpt
use socket2::{SockRef, TcpKeepalive, SetSockOpt}; 
use std::{future::Future, net::SocketAddr, time::Duration};
// 🌟 引入 Unix 系统的 AsRawFd trait
use std::os::unix::io::AsRawFd; 
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::{
    net::{lookup_host, TcpStream, ToSocketAddrs, UdpSocket},
    sync::broadcast,
};
use tracing::trace;
use url::Url;

use crate::transport::AddrMaybeCached;

// ... try_set_tcp_keepalive 保持不变 ...
pub fn try_set_tcp_keepalive(
    conn: &TcpStream,
    keepalive_duration: Duration,
    keepalive_interval: Duration,
) -> Result<()> {
    // ... (保持不变)
    // ...
    Ok(s.set_tcp_keepalive(&keepalive)?)
}


// 🌟 修改后的函数: 使用最底层的 setsockopt 逻辑
pub fn try_set_tcp_keepcnt(
    conn: &TcpStream, 
    probes: u32 // TCP_KEEPCNT
) -> Result<()> {
    
    if probes == 0 {
        return Ok(());
    }

    trace!("Set TCP keepcnt {}", probes);

    // 针对 Unix/Linux 系统 (包括 OpenWrt)
    #[cfg(target_family = "unix")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = conn.as_raw_fd();
        
        // 使用 libc 提供的 setsockopt
        // SOL_TCP 和 TCP_KEEPCNT 是 Linux 标准常量
        unsafe {
            // 设置 TCP_KEEPCNT
            let ret = libc::setsockopt(
                fd,
                libc::SOL_TCP,
                libc::TCP_KEEPCNT,
                &probes as *const u32 as *const libc::c_void,
                std::mem::size_of_val(&probes) as libc::socklen_t,
            );
            if ret != 0 {
                return Err(std::io::Error::last_os_error()).context("Failed to set TCP_KEEPCNT");
            }
        }
    }

    // 针对 Windows 系统 (如果 Rathole 支持 Windows)
    #[cfg(target_family = "windows")]
    {
        // Windows 的 socket 选项需要不同的处理，
        // 这里暂时留空或使用 socket2::set_opt(Level::Tcp, SocketOption::TcpKeepCount, probes)
        // 假设 OpenWrt/Linux 是主要目标，我们专注于 Unix 上的 libc 实现
    }

    Ok(())
}

// ... 后续代码保持不变 ...
