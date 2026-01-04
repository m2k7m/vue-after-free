// Full-Featured FTP Server for PS4
// Opens on port 42069
import { fn, BigInt, mem, utils } from 'download0/types'

include('userland.js')

// ============================================================================
// Configuration
// ============================================================================

const FTP_PORT = 0
const FTP_ROOT = '/'  // Root filesystem
const MAX_CLIENTS = 4
const PASV_PORT_MIN = 50000
const PASV_PORT_MAX = 50100

// ============================================================================
// Register FTP syscalls
// ============================================================================

// Basic I/O syscalls
fn.register(3, 'read', ['number', 'bigint', 'number'], 'bigint')
fn.register(4, 'write', ['number', 'bigint', 'number'], 'bigint')
fn.register(5, 'open', ['string', 'number', 'number'], 'bigint')
fn.register(6, 'close', ['number'], 'bigint')

// Socket syscalls (correct numbers from constants.py)
fn.register(97, 'socket', ['number', 'number', 'number'], 'bigint')
fn.register(104, 'bind', ['number', 'bigint', 'number'], 'bigint')
fn.register(105, 'setsockopt', ['number', 'number', 'number', 'bigint', 'number'], 'bigint')
fn.register(106, 'listen', ['number', 'number'], 'bigint')
fn.register(30, 'accept', ['number', 'number', 'number'], 'bigint')
fn.register(32, 'getsockname', ['number', 'bigint', 'bigint'], 'bigint')
fn.register(98, 'connect', ['number'], 'bigint')

// File syscalls
fn.register(0xBC, 'stat', ['string', 'bigint'], 'bigint')
fn.register(0x0A, 'unlink', ['string'], 'bigint')
fn.register(0x80, 'rename', ['string', 'string'], 'bigint')
fn.register(0x88, 'mkdir', ['string', 'number'], 'bigint')
fn.register(0x89, 'rmdir', ['string'], 'bigint')
fn.register(0x110, 'getdents', ['number', 'bigint', 'number'], 'bigint')
fn.register(0x1DE, 'lseek', ['number'], 'bigint')

// Use registered syscalls
const read_sys = fn.read
const write_sys = fn.write
const open_sys = fn.open
const close_sys = fn.close
const socket_sys = fn.socket
const bind_sys = fn.bind
const accept_sys = fn.accept
const setsockopt_sys = fn.setsockopt
const getsockname_sys = fn.getsockname
const connect_sys = fn.connect
const stat_sys = fn.stat
const unlink_sys = fn.unlink
const rename_sys = fn.rename
const mkdir_sys = fn.mkdir
const rmdir_sys = fn.rmdir
const getdents_sys = fn.getdents
const lseek_sys = fn.lseek

const listen_sys = fn.listen

// ============================================================================
// Socket constants
// ============================================================================

const AF_INET = 2
const SOCK_STREAM = 1
const SOL_SOCKET = 0xFFFF
const SO_REUSEADDR = 0x4

// File constants
const O_RDONLY = 0x0000
const O_WRONLY = 0x0001
const O_RDWR = 0x0002
const O_CREAT = 0x0200
const O_TRUNC = 0x0400

const S_IFMT = 0xF000
const S_IFDIR = 0x4000
const S_IFREG = 0x8000

// ============================================================================
// Global state
// ============================================================================

const current_pasv_port = PASV_PORT_MIN
const rename_from = null

// ============================================================================
// Helper functions
// ============================================================================

function aton (ip_str: string) {
  const [a, b, c, d] = ip_str.split('.')
  let result = 0
  result |= (parseInt(a!) << 24)
  result |= (parseInt(b!) << 16)
  result |= (parseInt(c!) << 8)
  result |= parseInt(d!)
  return result
}

function htons (port: number) {
  return ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)
}

function new_tcp_socket () {
  const sd = socket_sys(AF_INET, SOCK_STREAM, 0)

  if (sd.eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) {
    throw new Error('socket() failed')
  }
  return sd.lo
}

function send_response (client_fd: number, code: string, message: string) {
  const response = code + ' ' + message + '\r\n'

  const buf = mem.malloc(response.length + 1)
  for (let i = 0; i < response.length; i++) {
    mem.view(buf).setUint8(i, response.charCodeAt(i))
  }
  mem.view(buf).setUint8(response.length, 0)

  write_sys(client_fd, buf, response.length)
}

function read_line (client_fd: number) {
  const buf = mem.malloc(1024)
  let line = ''
  let total = 0

  while (total < 1023) {
    const ret = read_sys(client_fd, buf.add(new BigInt(0, total)), 1)

    if (ret.eq(new BigInt(0)) || ret.eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) {
      break
    }

    const ch = mem.view(buf).getUint8(total)
    total++

    if (ch === 10) break  // LF
    if (ch !== 13) {  // Skip CR
      line += String.fromCharCode(ch)
    }
  }

  return line
}

function build_path (base: string, path: string) {
  if (path.charAt(0) === '/') {
    return FTP_ROOT + path
  }
  return base + '/' + path
}

function format_file_mode (mode: number) {
  let str = ''

  if ((mode & S_IFMT) === S_IFDIR) {
    str += 'd'
  } else {
    str += '-'
  }

  str += (mode & 0x100) ? 'r' : '-'
  str += (mode & 0x080) ? 'w' : '-'
  str += (mode & 0x040) ? 'x' : '-'
  str += (mode & 0x020) ? 'r' : '-'
  str += (mode & 0x010) ? 'w' : '-'
  str += (mode & 0x008) ? 'x' : '-'
  str += (mode & 0x004) ? 'r' : '-'
  str += (mode & 0x002) ? 'w' : '-'
  str += (mode & 0x001) ? 'x' : '-'

  return str
}

// ============================================================================
// PASV mode support
// ============================================================================

function create_pasv_socket () {
  const data_fd = new_tcp_socket()

  const enable = mem.malloc(4)
  mem.view(enable).setUint32(0, 1, true)
  setsockopt_sys(data_fd, SOL_SOCKET, SO_REUSEADDR, enable, 4)

  // Use port 0 to let OS assign a free ephemeral port
  const data_addr = mem.malloc(16)
  mem.view(data_addr).setUint8(1, AF_INET)
  mem.view(data_addr).setUint16(2, 0, false)  // port 0 = OS assigns
  mem.view(data_addr).setUint32(4, 0, false)  // INADDR_ANY

  let ret = bind_sys(data_fd, data_addr, 16)
  if (ret.lo !== 0 && ret.hi !== 0xFFFFFFFF) {
    close_sys(data_fd)
    return null
  }

  ret = listen_sys(data_fd, 1)
  if (ret.lo !== 0 && ret.hi !== 0xFFFFFFFF) {
    close_sys(data_fd)
    return null
  }

  // Get the actual port assigned by OS using getsockname
  const actual_addr = mem.malloc(16)
  const addrlen = mem.malloc(4)
  mem.view(addrlen).setUint32(0, 16, true)

  ret = getsockname_sys(data_fd, actual_addr, addrlen)
  if (ret.lo !== 0 && ret.hi !== 0xFFFFFFFF) {
    close_sys(data_fd)
    return null
  }

  // Read port in network byte order (big-endian)
  const actual_port = mem.view(actual_addr).getUint16(2, false)

  return { fd: data_fd, port: actual_port }
}

function accept_data_connection (pasv_fd: number) {
  const client_ret = accept_sys(pasv_fd, 0, 0)
  const client_fd = client_ret.lo

  if (client_fd < 0) {
    return -1
  }

  return client_fd
}

// ============================================================================
// FTP command handlers
// ============================================================================

type State = {
  cwd: string,
  type: string,
  pasv_fd: number,
  pasv_port: number,
  rename_from: string | null
}

function handle_user (client_fd: number, _args: string, _state: unknown) {
  send_response(client_fd, '331', 'Username OK, any password accepted')
}

function handle_pass (client_fd: number, _args: string, _state: unknown) {
  send_response(client_fd, '230', 'Login successful')
}

function handle_syst (client_fd: number, _args: string, _state: unknown) {
  send_response(client_fd, '215', 'UNIX Type: L8')
}

function handle_pwd (client_fd: number, _args: string, state: State) {
  send_response(client_fd, '257', '"' + state.cwd + '" is current directory')
}

function handle_cwd (client_fd: number, args: string, state: State) {
  if (!args || args === '') {
    send_response(client_fd, '500', 'Syntax error, command unrecognized')
    return
  }

  // Handle special cases
  if (args === '/') {
    state.cwd = '/'
    send_response(client_fd, '250', 'Requested file action okay, completed')
    return
  }

  if (args === '..') {
    // Go up one directory
    if (state.cwd === '/') {
      send_response(client_fd, '250', 'Requested file action okay, completed')
    } else {
      const last_slash = state.cwd.lastIndexOf('/')
      if (last_slash === 0) {
        state.cwd = '/'
      } else {
        state.cwd = state.cwd.substring(0, last_slash)
      }
      send_response(client_fd, '250', 'Requested file action okay, completed')
    }
    return
  }

  // Build new path (absolute vs relative)
  let new_path
  if (args.charAt(0) === '/') {
    new_path = args
  } else {
    if (state.cwd === '/') {
      new_path = '/' + args
    } else {
      new_path = state.cwd + '/' + args
    }
  }

  // Test if directory exists by trying to open it
  const fd = open_sys(new_path, O_RDONLY, 0).lo

  if (fd < 0) {
    // Path doesn't exist - check if it looks like a file path
    const last_slash = new_path.lastIndexOf('/')
    if (last_slash > 0) {
      const filename = new_path.substring(last_slash + 1)
      // If it has an extension or looks like a file, navigate to parent dir instead
      if (filename.indexOf('.') > 0 || filename.length > 0) {
        let parent_dir = new_path.substring(0, last_slash)
        if (parent_dir === '') parent_dir = '/'

        const parent_fd = open_sys(parent_dir, O_RDONLY, 0).lo

        if (parent_fd >= 0) {
          close_sys(parent_fd)
          state.cwd = parent_dir
          send_response(client_fd, '250', 'Requested file action okay, completed')
          return
        }
      }
    }

    send_response(client_fd, '550', 'Invalid directory')
    return
  }

  close_sys(fd)
  state.cwd = new_path
  send_response(client_fd, '250', 'Requested file action okay, completed')
}

function handle_cdup (client_fd: number, _args: string, state: State) {
  handle_cwd(client_fd, '..', state)
}

function handle_type (client_fd: number, args: string, state: State) {
  state.type = args.toUpperCase()
  send_response(client_fd, '200', 'Type set to ' + state.type)
}

function handle_pasv (client_fd: number, _args: string, state: State) {
  const pasv = create_pasv_socket()
  if (!pasv) {
    send_response(client_fd, '425', 'Cannot open passive connection')
    return
  }

  state.pasv_fd = pasv.fd
  state.pasv_port = pasv.port

  // Get the server's local IP from the control connection
  const local_addr = mem.malloc(16)
  const addrlen = mem.malloc(4)
  mem.view(addrlen).setUint32(0, 16, true)

  const ret = getsockname_sys(client_fd, local_addr, addrlen)

  let ip_bytes = [0, 0, 0, 0]
  if (ret.eq(new BigInt(0))) {
    // Read IP address in network byte order (big-endian) at offset 4
    const ip_addr = mem.view(local_addr).getUint32(4, false)  // big-endian
    ip_bytes[0] = (ip_addr >> 24) & 0xFF
    ip_bytes[1] = (ip_addr >> 16) & 0xFF
    ip_bytes[2] = (ip_addr >> 8) & 0xFF
    ip_bytes[3] = ip_addr & 0xFF
  } else {
    // Fallback to localhost if getsockname fails
    ip_bytes = [127, 0, 0, 1]
  }

  const p1 = (pasv.port >> 8) & 0xFF
  const p2 = pasv.port & 0xFF

  send_response(client_fd, '227', 'Entering Passive Mode (' + ip_bytes[0] + ',' + ip_bytes[1] + ',' + ip_bytes[2] + ',' + ip_bytes[3] + ',' + p1 + ',' + p2 + ')')
}

function handle_list (client_fd: number, _args: string, state: State) {
  if (!state.pasv_fd || state.pasv_fd < 0) {
    send_response(client_fd, '425', 'Use PASV first')
    return
  }

  // Ignore flags like -a, -l, etc. and just list current directory
  const path = state.cwd === '/' ? '/' : state.cwd

  send_response(client_fd, '150', 'Opening ASCII mode data connection for file list')

  const data_fd = accept_data_connection(state.pasv_fd)
  if (data_fd < 0) {
    send_response(client_fd, '426', 'Connection closed; transfer aborted')
    close_sys(state.pasv_fd)
    state.pasv_fd = -1
    return
  }

  // Open directory
  const dir_fd = open_sys(path, O_RDONLY, 0).lo

  if (dir_fd >= 0) {
    const dirent_buf = mem.malloc(1024)

    while (true) {
      const ret = getdents_sys(dir_fd, dirent_buf, 1024).lo

      if (ret <= 0) break

      let offset = 0
      while (offset < ret) {
        const d_fileno = mem.view(dirent_buf).getUint32(offset, true)
        const d_reclen = mem.view(dirent_buf).getUint16(offset + 4, true)
        const d_type = mem.view(dirent_buf).getUint8(offset + 6)
        const d_namlen = mem.view(dirent_buf).getUint8(offset + 7)

        let name = ''
        for (let i = 0; i < d_namlen; i++) {
          name += String.fromCharCode(mem.view(dirent_buf).getUint8(offset + 8 + i))
        }

        if (name !== '.' && name !== '..') {
          const line = format_file_mode(d_type === 4 ? S_IFDIR : S_IFREG) + ' 1 root root 4096 Jan 1 2024 ' + name + '\r\n'
          const line_buf = mem.malloc(line.length)
          for (let j = 0; j < line.length; j++) {
            mem.view(line_buf).setUint8(j, line.charCodeAt(j))
          }
          write_sys(data_fd, line_buf, line.length)
        }

        offset += d_reclen
      }
    }

    close_sys(dir_fd)
  }

  close_sys(data_fd)
  close_sys(state.pasv_fd)
  state.pasv_fd = -1

  send_response(client_fd, '226', 'Transfer complete')
}

function handle_retr (client_fd: number, args: string, state: State) {
  if (!state.pasv_fd || state.pasv_fd < 0) {
    send_response(client_fd, '425', 'Use PASV first')
    return
  }

  const path = build_path(state.cwd, args)

  const file_fd = open_sys(path, O_RDONLY, 0).lo
  if (file_fd < 0) {
    send_response(client_fd, '550', 'File not found')
    close_sys(state.pasv_fd)
    state.pasv_fd = -1
    return
  }

  send_response(client_fd, '150', 'Opening BINARY mode data connection')

  const data_fd = accept_data_connection(state.pasv_fd)
  if (data_fd < 0) {
    send_response(client_fd, '426', 'Connection closed; transfer aborted')
    close_sys(file_fd)
    close_sys(state.pasv_fd)
    state.pasv_fd = -1
    return
  }

  const chunk_size = 8192
  const buf = mem.malloc(chunk_size)

  while (true) {
    const ret = read_sys(file_fd, buf, chunk_size).lo

    if (ret <= 0) break

    write_sys(data_fd, buf, ret)
  }

  close_sys(file_fd)
  close_sys(data_fd)
  close_sys(state.pasv_fd)
  state.pasv_fd = -1

  send_response(client_fd, '226', 'Transfer complete')
}

function handle_stor (client_fd: number, args: string, state: State) {
  if (!state.pasv_fd || state.pasv_fd < 0) {
    send_response(client_fd, '425', 'Use PASV first')
    return
  }

  const path = build_path(state.cwd, args)

  const file_fd = open_sys(path, O_WRONLY | O_CREAT | O_TRUNC, 0o666).lo
  if (file_fd < 0) {
    send_response(client_fd, '550', 'Cannot create file')
    close_sys(state.pasv_fd)
    state.pasv_fd = -1
    return
  }

  send_response(client_fd, '150', 'Opening BINARY mode data connection')

  const data_fd = accept_data_connection(state.pasv_fd)
  if (data_fd < 0) {
    send_response(client_fd, '426', 'Connection closed; transfer aborted')
    close_sys(file_fd)
    close_sys(state.pasv_fd)
    state.pasv_fd = -1
    return
  }

  const chunk_size = 8192
  const buf = mem.malloc(chunk_size)

  while (true) {
    const ret = read_sys(data_fd, buf, chunk_size).lo

    if (ret <= 0) break

    write_sys(file_fd, buf, ret)
  }

  close_sys(file_fd)
  close_sys(data_fd)
  close_sys(state.pasv_fd)
  state.pasv_fd = -1

  send_response(client_fd, '226', 'Transfer complete')
}

function handle_dele (client_fd: number, args: string, state: State) {
  const path = build_path(state.cwd, args)

  const ret = unlink_sys(path)
  if (ret.eq(new BigInt(0))) {
    send_response(client_fd, '250', 'File deleted')
  } else {
    send_response(client_fd, '550', 'Delete failed')
  }
}

function handle_mkd (client_fd: number, args: string, state: State) {
  const path = build_path(state.cwd, args)

  const ret = mkdir_sys(path, 0x1FF)  // 0777
  if (ret.eq(new BigInt(0))) {
    send_response(client_fd, '257', '"' + path + '" directory created')
  } else {
    send_response(client_fd, '550', 'Create directory failed')
  }
}

function handle_rmd (client_fd: number, args: string, state: State) {
  const path = build_path(state.cwd, args)

  const ret = rmdir_sys(path)
  if (ret.eq(new BigInt(0))) {
    send_response(client_fd, '250', 'Directory removed')
  } else {
    send_response(client_fd, '550', 'Remove directory failed')
  }
}

function handle_rnfr (client_fd: number, args: string, state: State) {
  state.rename_from = build_path(state.cwd, args)
  send_response(client_fd, '350', 'Ready for RNTO')
}

function handle_rnto (client_fd: number, args: string, state: State) {
  if (!state.rename_from) {
    send_response(client_fd, '503', 'Bad sequence of commands')
    return
  }

  const path_to = build_path(state.cwd, args)

  const ret = rename_sys(state.rename_from, path_to)
  if (ret.eq(new BigInt(0))) {
    send_response(client_fd, '250', 'Rename successful')
  } else {
    send_response(client_fd, '550', 'Rename failed')
  }

  state.rename_from = null
}

function handle_size (client_fd: number, args: string, state: State) {
  const path = build_path(state.cwd, args)

  const statbuf = mem.malloc(144)  // sizeof(struct stat)
  const ret = stat_sys(path, statbuf)

  if (ret.eq(new BigInt(0))) {
    const size = mem.view(statbuf).getBigInt(48, true)  // st_size offset
    send_response(client_fd, '213', size.toString())
  } else {
    send_response(client_fd, '550', 'Could not get file size')
  }
}

function handle_quit (client_fd: number, _args: string, _state: State) {
  send_response(client_fd, '221', 'Goodbye')
}

function handle_noop (client_fd: number, _args: string, _state: State) {
  send_response(client_fd, '200', 'OK')
}

function handle_client (client_fd: number, client_num: number) {
  const state: State = {
    cwd: '/',
    type: 'A',
    pasv_fd: -1,
    pasv_port: -1,
    rename_from: null
  }

  try {
    send_response(client_fd, '220', 'PS4 FTP Server Ready')

    let running = true
    while (running) {
      const line = read_line(client_fd)
      if (line.length === 0) break

      const parts = line.split(' ')
      const cmd = parts[0]!.toUpperCase()
      const args = parts.slice(1).join(' ')

      if (cmd === 'USER') {
        handle_user(client_fd, args, state)
      } else if (cmd === 'PASS') {
        handle_pass(client_fd, args, state)
      } else if (cmd === 'SYST') {
        handle_syst(client_fd, args, state)
      } else if (cmd === 'PWD') {
        handle_pwd(client_fd, args, state)
      } else if (cmd === 'CWD') {
        handle_cwd(client_fd, args, state)
      } else if (cmd === 'CDUP') {
        handle_cdup(client_fd, args, state)
      } else if (cmd === 'TYPE') {
        handle_type(client_fd, args, state)
      } else if (cmd === 'PASV') {
        handle_pasv(client_fd, args, state)
      } else if (cmd === 'LIST') {
        handle_list(client_fd, args, state)
      } else if (cmd === 'RETR') {
        handle_retr(client_fd, args, state)
      } else if (cmd === 'STOR') {
        handle_stor(client_fd, args, state)
      } else if (cmd === 'DELE') {
        handle_dele(client_fd, args, state)
      } else if (cmd === 'MKD' || cmd === 'XMKD') {
        handle_mkd(client_fd, args, state)
      } else if (cmd === 'RMD' || cmd === 'XRMD') {
        handle_rmd(client_fd, args, state)
      } else if (cmd === 'RNFR') {
        handle_rnfr(client_fd, args, state)
      } else if (cmd === 'RNTO') {
        handle_rnto(client_fd, args, state)
      } else if (cmd === 'SIZE') {
        handle_size(client_fd, args, state)
      } else if (cmd === 'NOOP') {
        handle_noop(client_fd, args, state)
      } else if (cmd === 'QUIT') {
        handle_quit(client_fd, args, state)
        running = false
      } else {
        send_response(client_fd, '502', 'Command not implemented')
      }
    }
  } catch (e) {
    // Silent error handling
  } finally {
    if (state.pasv_fd >= 0) {
      close_sys(state.pasv_fd)
    }
    close_sys(client_fd)
  }
}

// ============================================================================
// Main FTP server
// ============================================================================

function start_ftp_server () {
  try {
    // Create server socket
    const server_fd = new_tcp_socket()

    // Set SO_REUSEADDR
    const enable = mem.malloc(4)
    mem.view(enable).setUint32(0, 1, true)
    setsockopt_sys(server_fd, SOL_SOCKET, SO_REUSEADDR, enable, 4)

    // Bind to 0.0.0.0:42069
    // struct sockaddr_in: family at offset 1, port at offset 2, addr at offset 4
    const server_addr = mem.malloc(16)
    mem.view(server_addr).setUint8(1, AF_INET)
    mem.view(server_addr).setUint16(2, htons(FTP_PORT), false)  // network byte order
    mem.view(server_addr).setUint32(4, 0, false)  // INADDR_ANY (0.0.0.0)

    let ret = bind_sys(server_fd, server_addr, 16)
    if (ret.lo !== 0 && ret.hi !== 0xFFFFFFFF) {
      throw new Error('bind() failed')
    }

    // Get the actual port that was bound using getsockname
    const actual_addr = mem.malloc(16)
    const addrlen = mem.malloc(4)
    mem.view(addrlen).setUint32(0, 16, true)

    ret = getsockname_sys(server_fd, actual_addr, addrlen)
    if (ret.lo !== 0 && ret.hi !== 0xFFFFFFFF) {
      throw new Error('getsockname() failed')
    }

    // Read port in network byte order (big-endian) at offset 2
    const actual_port = mem.view(actual_addr).getUint16(2, false)  // big-endian

    // Listen
    ret = listen_sys(server_fd, MAX_CLIENTS)
    if (ret.lo !== 0 && ret.hi !== 0xFFFFFFFF) {
      throw new Error('listen() failed')
    }

    // Get server IP from sockaddr
    const ip_addr = mem.view(actual_addr).getUint32(4, false)  // big-endian at offset 4
    const ip_bytes = [
      (ip_addr >> 24) & 0xFF,
      (ip_addr >> 16) & 0xFF,
      (ip_addr >> 8) & 0xFF,
      ip_addr & 0xFF
    ]
    const ip_str = ip_bytes[0] + '.' + ip_bytes[1] + '.' + ip_bytes[2] + '.' + ip_bytes[3]

    // Send notification with IP and port
    utils.notify('FTP: ' + ip_str + ':' + actual_port)

    // Accept loop
    let client_num = 0
    while (true) {
      const client_ret = accept_sys(server_fd, 0, 0)
      const client_fd = client_ret.lo

      if (client_fd < 0) {
        continue
      }

      client_num++
      handle_client(client_fd, client_num)
    }
  } catch (e) {
    utils.notify('FTP Error: ' + (e as Error).message)
  }
}

// Start the server
start_ftp_server()
