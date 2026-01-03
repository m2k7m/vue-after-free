// Full-Featured FTP Server for PS4
// Opens on port 42069

include('inject.js')

jsmaf.remotePlay = true

// ============================================================================
// Configuration
// ============================================================================

var FTP_PORT = 0
var FTP_ROOT = '/'  // Root filesystem
var MAX_CLIENTS = 4
var PASV_PORT_MIN = 50000
var PASV_PORT_MAX = 50100

// ============================================================================
// Register FTP syscalls
// ============================================================================

// Basic I/O syscalls
try { fn.register(3, 'read', 'bigint') } catch(e) {}

// Socket syscalls (correct numbers from constants.py)
try { fn.register(97, 'socket', 'bigint') } catch(e) {}
try { fn.register(104, 'bind', 'bigint') } catch(e) {}
try { fn.register(105, 'setsockopt', 'bigint') } catch(e) {}
try { fn.register(106, 'listen', 'bigint') } catch(e) {}
try { fn.register(30, 'accept', 'bigint') } catch(e) {}
try { fn.register(32, 'getsockname', 'bigint') } catch(e) {}
try { fn.register(98, 'connect', 'bigint') } catch(e) {}

// File syscalls
try { fn.register(0xBC, 'stat', 'bigint') } catch(e) {}
try { fn.register(0x0A, 'unlink', 'bigint') } catch(e) {}
try { fn.register(0x80, 'rename', 'bigint') } catch(e) {}
try { fn.register(0x88, 'mkdir', 'bigint') } catch(e) {}
try { fn.register(0x89, 'rmdir', 'bigint') } catch(e) {}
try { fn.register(0x110, 'getdents', 'bigint') } catch(e) {}
try { fn.register(0x1DE, 'lseek', 'bigint') } catch(e) {}

// Use registered syscalls
var read_sys = fn.read
var write_sys = fn.write
var close_sys = fn.close
var socket_sys = fn.socket
var bind_sys = fn.bind
var accept_sys = fn.accept
var setsockopt_sys = fn.setsockopt
var getsockname_sys = fn.getsockname
var connect_sys = fn.connect
var stat_sys = fn.stat
var unlink_sys = fn.unlink
var rename_sys = fn.rename
var mkdir_sys = fn.mkdir
var rmdir_sys = fn.rmdir
var getdents_sys = fn.getdents
var lseek_sys = fn.lseek

var listen_sys = fn.listen

// ============================================================================
// Socket constants
// ============================================================================

var AF_INET = 2
var SOCK_STREAM = 1
var SOL_SOCKET = 0xFFFF
var SO_REUSEADDR = 0x4

// File constants
var O_RDONLY = 0x0000
var O_WRONLY = 0x0001
var O_RDWR = 0x0002
var O_CREAT = 0x0200
var O_TRUNC = 0x0400

var S_IFMT = 0xF000
var S_IFDIR = 0x4000
var S_IFREG = 0x8000

// ============================================================================
// Global state
// ============================================================================

var current_pasv_port = PASV_PORT_MIN
var rename_from = null

// ============================================================================
// Helper functions
// ============================================================================

function aton(ip_str) {
  var parts = ip_str.split('.')
  var result = 0
  result |= (parseInt(parts[0]) << 24)
  result |= (parseInt(parts[1]) << 16)
  result |= (parseInt(parts[2]) << 8)
  result |= parseInt(parts[3])
  return result
}

function htons(port) {
  return ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)
}

function new_tcp_socket() {
  var sd = socket_sys(AF_INET, SOCK_STREAM, 0)

  if (sd instanceof BigInt) {
    if (sd.eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) {
      throw new Error('socket() failed')
    }
    return sd.lo
  }

  if (sd === -1) {
    throw new Error('socket() failed')
  }

  return sd
}

function send_response(client_fd, code, message) {
  var response = code + ' ' + message + '\r\n'

  var buf = mem.malloc(response.length + 1)
  for (var i = 0; i < response.length; i++) {
    mem.view(buf).setUint8(i, response.charCodeAt(i))
  }
  mem.view(buf).setUint8(response.length, 0)

  write_sys(client_fd, buf, response.length)
}

function read_line(client_fd) {
  var buf = mem.malloc(1024)
  var line = ''
  var total = 0

  while (total < 1023) {
    var ret = read_sys(client_fd, buf.add(new BigInt(0, total)), 1)

    if (ret instanceof BigInt) {
      if (ret.eq(BigInt.Zero) || ret.eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) {
        break
      }
      ret = ret.lo
    }

    if (ret <= 0) break

    var ch = mem.view(buf).getUint8(total)
    total++

    if (ch === 10) break  // LF
    if (ch !== 13) {  // Skip CR
      line += String.fromCharCode(ch)
    }
  }

  return line
}

function build_path(base, path) {
  if (path.charAt(0) === '/') {
    return FTP_ROOT + path
  }
  return base + '/' + path
}

function format_file_mode(mode) {
  var str = ''

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

function create_pasv_socket() {
  var data_fd = new_tcp_socket()

  var enable = mem.malloc(4)
  mem.view(enable).setUint32(0, 1, true)
  setsockopt_sys(data_fd, SOL_SOCKET, SO_REUSEADDR, enable, 4)

  // Use port 0 to let OS assign a free ephemeral port
  var data_addr = mem.malloc(16)
  mem.view(data_addr).setUint8(1, AF_INET)
  mem.view(data_addr).setUint16(2, 0, false)  // port 0 = OS assigns
  mem.view(data_addr).setUint32(4, 0, false)  // INADDR_ANY

  var ret = bind_sys(data_fd, data_addr, 16)
  if (ret instanceof BigInt && ret.lo !== 0 && ret.hi !== 0xFFFFFFFF) {
    close_sys(data_fd)
    return null
  }

  ret = listen_sys(data_fd, 1)
  if (ret instanceof BigInt && ret.lo !== 0 && ret.hi !== 0xFFFFFFFF) {
    close_sys(data_fd)
    return null
  }

  // Get the actual port assigned by OS using getsockname
  var actual_addr = mem.malloc(16)
  var addrlen = mem.malloc(4)
  mem.view(addrlen).setUint32(0, 16, true)

  ret = getsockname_sys(data_fd, actual_addr, addrlen)
  if (ret instanceof BigInt && ret.lo !== 0 && ret.hi !== 0xFFFFFFFF) {
    close_sys(data_fd)
    return null
  }

  // Read port in network byte order (big-endian)
  var actual_port = mem.view(actual_addr).getUint16(2, false)

  return { fd: data_fd, port: actual_port }
}

function accept_data_connection(pasv_fd) {
  var client_ret = accept_sys(pasv_fd, 0, 0)
  var client_fd = client_ret instanceof BigInt ? client_ret.lo : client_ret

  if (client_fd < 0) {
    return -1
  }

  return client_fd
}

// ============================================================================
// FTP command handlers
// ============================================================================

function handle_user(client_fd, args, state) {
  send_response(client_fd, '331', 'Username OK, any password accepted')
}

function handle_pass(client_fd, args, state) {
  send_response(client_fd, '230', 'Login successful')
}

function handle_syst(client_fd, args, state) {
  send_response(client_fd, '215', 'UNIX Type: L8')
}

function handle_pwd(client_fd, args, state) {
  send_response(client_fd, '257', '"' + state.cwd + '" is current directory')
}

function handle_cwd(client_fd, args, state) {
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
      var last_slash = state.cwd.lastIndexOf('/')
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
  var new_path
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
  var path_str = mem.malloc(new_path.length + 1)
  for (var i = 0; i < new_path.length; i++) {
    mem.view(path_str).setUint8(i, new_path.charCodeAt(i))
  }
  mem.view(path_str).setUint8(new_path.length, 0)

  var fd = fn.open(path_str, O_RDONLY, 0)
  if (fd instanceof BigInt) {
    fd = fd.lo
  }

  if (fd < 0) {
    // Path doesn't exist - check if it looks like a file path
    var last_slash = new_path.lastIndexOf('/')
    if (last_slash > 0) {
      var filename = new_path.substring(last_slash + 1)
      // If it has an extension or looks like a file, navigate to parent dir instead
      if (filename.indexOf('.') > 0 || filename.length > 0) {
        var parent_dir = new_path.substring(0, last_slash)
        if (parent_dir === '') parent_dir = '/'


        // Try parent directory
        var parent_str = mem.malloc(parent_dir.length + 1)
        for (var i = 0; i < parent_dir.length; i++) {
          mem.view(parent_str).setUint8(i, parent_dir.charCodeAt(i))
        }
        mem.view(parent_str).setUint8(parent_dir.length, 0)

        var parent_fd = fn.open(parent_str, O_RDONLY, 0)
        if (parent_fd instanceof BigInt) {
          parent_fd = parent_fd.lo
        }

        if (parent_fd >= 0) {
          fn.close(parent_fd)
          state.cwd = parent_dir
          send_response(client_fd, '250', 'Requested file action okay, completed')
          return
        }
      }
    }

    send_response(client_fd, '550', 'Invalid directory')
    return
  }

  fn.close(fd)
  state.cwd = new_path
  send_response(client_fd, '250', 'Requested file action okay, completed')
}

function handle_cdup(client_fd, args, state) {
  handle_cwd(client_fd, '..', state)
}

function handle_type(client_fd, args, state) {
  state.type = args.toUpperCase()
  send_response(client_fd, '200', 'Type set to ' + state.type)
}

function handle_pasv(client_fd, args, state) {
  var pasv = create_pasv_socket()
  if (!pasv) {
    send_response(client_fd, '425', 'Cannot open passive connection')
    return
  }

  state.pasv_fd = pasv.fd
  state.pasv_port = pasv.port

  // Get the server's local IP from the control connection
  var local_addr = mem.malloc(16)
  var addrlen = mem.malloc(4)
  mem.view(addrlen).setUint32(0, 16, true)

  var ret = getsockname_sys(client_fd, local_addr, addrlen)

  var ip_bytes = [0, 0, 0, 0]
  if (!ret || (ret instanceof BigInt && ret.eq(BigInt.Zero))) {
    // Read IP address in network byte order (big-endian) at offset 4
    var ip_addr = mem.view(local_addr).getUint32(4, false)  // big-endian
    ip_bytes[0] = (ip_addr >> 24) & 0xFF
    ip_bytes[1] = (ip_addr >> 16) & 0xFF
    ip_bytes[2] = (ip_addr >> 8) & 0xFF
    ip_bytes[3] = ip_addr & 0xFF
  } else {
    // Fallback to localhost if getsockname fails
    ip_bytes = [127, 0, 0, 1]
  }

  var p1 = (pasv.port >> 8) & 0xFF
  var p2 = pasv.port & 0xFF

  send_response(client_fd, '227', 'Entering Passive Mode (' + ip_bytes[0] + ',' + ip_bytes[1] + ',' + ip_bytes[2] + ',' + ip_bytes[3] + ',' + p1 + ',' + p2 + ')')
}

function handle_list(client_fd, args, state) {
  if (!state.pasv_fd || state.pasv_fd < 0) {
    send_response(client_fd, '425', 'Use PASV first')
    return
  }

  // Ignore flags like -a, -l, etc. and just list current directory
  var path = state.cwd === '/' ? '/' : state.cwd

  send_response(client_fd, '150', 'Opening ASCII mode data connection for file list')

  var data_fd = accept_data_connection(state.pasv_fd)
  if (data_fd < 0) {
    send_response(client_fd, '426', 'Connection closed; transfer aborted')
    close_sys(state.pasv_fd)
    state.pasv_fd = -1
    return
  }

  // Open directory
  var path_str = mem.malloc(path.length + 1)
  for (var i = 0; i < path.length; i++) {
    mem.view(path_str).setUint8(i, path.charCodeAt(i))
  }
  mem.view(path_str).setUint8(path.length, 0)

  var dir_fd = fn.open(path_str, O_RDONLY)
  if (dir_fd instanceof BigInt) {
    dir_fd = dir_fd.lo
  }

  if (dir_fd >= 0) {
    var dirent_buf = mem.malloc(1024)

    while (true) {
      var ret = getdents_sys(dir_fd, dirent_buf, 1024)
      if (ret instanceof BigInt) {
        ret = ret.lo
      }

      if (ret <= 0) break

      var offset = 0
      while (offset < ret) {
        var d_fileno = mem.view(dirent_buf).getUint32(offset, true)
        var d_reclen = mem.view(dirent_buf).getUint16(offset + 4, true)
        var d_type = mem.view(dirent_buf).getUint8(offset + 6)
        var d_namlen = mem.view(dirent_buf).getUint8(offset + 7)

        var name = ''
        for (var i = 0; i < d_namlen; i++) {
          name += String.fromCharCode(mem.view(dirent_buf).getUint8(offset + 8 + i))
        }

        if (name !== '.' && name !== '..') {
          var line = format_file_mode(d_type === 4 ? S_IFDIR : S_IFREG) + ' 1 root root 4096 Jan 1 2024 ' + name + '\r\n'
          var line_buf = mem.malloc(line.length)
          for (var j = 0; j < line.length; j++) {
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

function handle_retr(client_fd, args, state) {
  if (!state.pasv_fd || state.pasv_fd < 0) {
    send_response(client_fd, '425', 'Use PASV first')
    return
  }

  var path = build_path(state.cwd, args)

  var path_str = mem.malloc(path.length + 1)
  for (var i = 0; i < path.length; i++) {
    mem.view(path_str).setUint8(i, path.charCodeAt(i))
  }
  mem.view(path_str).setUint8(path.length, 0)

  var file_fd = fn.open(path_str, O_RDONLY)
  if (file_fd instanceof BigInt) {
    file_fd = file_fd.lo
  }

  if (file_fd < 0) {
    send_response(client_fd, '550', 'File not found')
    close_sys(state.pasv_fd)
    state.pasv_fd = -1
    return
  }

  send_response(client_fd, '150', 'Opening BINARY mode data connection')

  var data_fd = accept_data_connection(state.pasv_fd)
  if (data_fd < 0) {
    send_response(client_fd, '426', 'Connection closed; transfer aborted')
    close_sys(file_fd)
    close_sys(state.pasv_fd)
    state.pasv_fd = -1
    return
  }

  var chunk_size = 8192
  var buf = mem.malloc(chunk_size)

  while (true) {
    var ret = fn.read(file_fd, buf, chunk_size)
    if (ret instanceof BigInt) {
      ret = ret.lo
    }

    if (ret <= 0) break

    write_sys(data_fd, buf, ret)
  }

  close_sys(file_fd)
  close_sys(data_fd)
  close_sys(state.pasv_fd)
  state.pasv_fd = -1

  send_response(client_fd, '226', 'Transfer complete')
}

function handle_stor(client_fd, args, state) {
  if (!state.pasv_fd || state.pasv_fd < 0) {
    send_response(client_fd, '425', 'Use PASV first')
    return
  }

  var path = build_path(state.cwd, args)

  var path_str = mem.malloc(path.length + 1)
  for (var i = 0; i < path.length; i++) {
    mem.view(path_str).setUint8(i, path.charCodeAt(i))
  }
  mem.view(path_str).setUint8(path.length, 0)

  var file_fd = fn.open(path_str, O_WRONLY | O_CREAT | O_TRUNC, 0o666)
  if (file_fd instanceof BigInt) {
    file_fd = file_fd.lo
  }

  if (file_fd < 0) {
    send_response(client_fd, '550', 'Cannot create file')
    close_sys(state.pasv_fd)
    state.pasv_fd = -1
    return
  }

  send_response(client_fd, '150', 'Opening BINARY mode data connection')

  var data_fd = accept_data_connection(state.pasv_fd)
  if (data_fd < 0) {
    send_response(client_fd, '426', 'Connection closed; transfer aborted')
    close_sys(file_fd)
    close_sys(state.pasv_fd)
    state.pasv_fd = -1
    return
  }

  var chunk_size = 8192
  var buf = mem.malloc(chunk_size)

  while (true) {
    var ret = read_sys(data_fd, buf, chunk_size)
    if (ret instanceof BigInt) {
      ret = ret.lo
    }

    if (ret <= 0) break

    fn.write(file_fd, buf, ret)
  }

  close_sys(file_fd)
  close_sys(data_fd)
  close_sys(state.pasv_fd)
  state.pasv_fd = -1

  send_response(client_fd, '226', 'Transfer complete')
}

function handle_dele(client_fd, args, state) {
  var path = build_path(state.cwd, args)

  var path_str = mem.malloc(path.length + 1)
  for (var i = 0; i < path.length; i++) {
    mem.view(path_str).setUint8(i, path.charCodeAt(i))
  }
  mem.view(path_str).setUint8(path.length, 0)

  var ret = unlink_sys(path_str)
  if (ret instanceof BigInt && ret.eq(BigInt.Zero)) {
    send_response(client_fd, '250', 'File deleted')
  } else {
    send_response(client_fd, '550', 'Delete failed')
  }
}

function handle_mkd(client_fd, args, state) {
  var path = build_path(state.cwd, args)

  var path_str = mem.malloc(path.length + 1)
  for (var i = 0; i < path.length; i++) {
    mem.view(path_str).setUint8(i, path.charCodeAt(i))
  }
  mem.view(path_str).setUint8(path.length, 0)

  var ret = mkdir_sys(path_str, 0x1FF)  // 0777
  if (ret instanceof BigInt && ret.eq(BigInt.Zero)) {
    send_response(client_fd, '257', '"' + path + '" directory created')
  } else {
    send_response(client_fd, '550', 'Create directory failed')
  }
}

function handle_rmd(client_fd, args, state) {
  var path = build_path(state.cwd, args)

  var path_str = mem.malloc(path.length + 1)
  for (var i = 0; i < path.length; i++) {
    mem.view(path_str).setUint8(i, path.charCodeAt(i))
  }
  mem.view(path_str).setUint8(path.length, 0)

  var ret = rmdir_sys(path_str)
  if (ret instanceof BigInt && ret.eq(BigInt.Zero)) {
    send_response(client_fd, '250', 'Directory removed')
  } else {
    send_response(client_fd, '550', 'Remove directory failed')
  }
}

function handle_rnfr(client_fd, args, state) {
  state.rename_from = build_path(state.cwd, args)
  send_response(client_fd, '350', 'Ready for RNTO')
}

function handle_rnto(client_fd, args, state) {
  if (!state.rename_from) {
    send_response(client_fd, '503', 'Bad sequence of commands')
    return
  }

  var path_to = build_path(state.cwd, args)

  var from_str = mem.malloc(state.rename_from.length + 1)
  for (var i = 0; i < state.rename_from.length; i++) {
    mem.view(from_str).setUint8(i, state.rename_from.charCodeAt(i))
  }
  mem.view(from_str).setUint8(state.rename_from.length, 0)

  var to_str = mem.malloc(path_to.length + 1)
  for (var i = 0; i < path_to.length; i++) {
    mem.view(to_str).setUint8(i, path_to.charCodeAt(i))
  }
  mem.view(to_str).setUint8(path_to.length, 0)

  var ret = rename_sys(from_str, to_str)
  if (ret instanceof BigInt && ret.eq(BigInt.Zero)) {
    send_response(client_fd, '250', 'Rename successful')
  } else {
    send_response(client_fd, '550', 'Rename failed')
  }

  state.rename_from = null
}

function handle_size(client_fd, args, state) {
  var path = build_path(state.cwd, args)

  var path_str = mem.malloc(path.length + 1)
  for (var i = 0; i < path.length; i++) {
    mem.view(path_str).setUint8(i, path.charCodeAt(i))
  }
  mem.view(path_str).setUint8(path.length, 0)

  var statbuf = mem.malloc(144)  // sizeof(struct stat)
  var ret = stat_sys(path_str, statbuf)

  if (ret instanceof BigInt && ret.eq(BigInt.Zero)) {
    var size = mem.view(statbuf).getBigInt(48, true)  // st_size offset
    send_response(client_fd, '213', size.toString())
  } else {
    send_response(client_fd, '550', 'Could not get file size')
  }
}

function handle_quit(client_fd, args, state) {
  send_response(client_fd, '221', 'Goodbye')
}

function handle_noop(client_fd, args, state) {
  send_response(client_fd, '200', 'OK')
}

function handle_client(client_fd, client_num) {
  var state = {
    cwd: '/',
    type: 'A',
    pasv_fd: -1,
    pasv_port: -1,
    rename_from: null
  }

  try {
    send_response(client_fd, '220', 'PS4 FTP Server Ready')

    var running = true
    while (running) {
      var line = read_line(client_fd)
      if (line.length === 0) break

      var parts = line.split(' ')
      var cmd = parts[0].toUpperCase()
      var args = parts.slice(1).join(' ')

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

function start_ftp_server() {
  try {
    // Create server socket
    var server_fd = new_tcp_socket()

    // Set SO_REUSEADDR
    var enable = mem.malloc(4)
    mem.view(enable).setUint32(0, 1, true)
    setsockopt_sys(server_fd, SOL_SOCKET, SO_REUSEADDR, enable, 4)

    // Bind to 0.0.0.0:42069
    // struct sockaddr_in: family at offset 1, port at offset 2, addr at offset 4
    var server_addr = mem.malloc(16)
    mem.view(server_addr).setUint8(1, AF_INET)
    mem.view(server_addr).setUint16(2, htons(FTP_PORT), false)  // network byte order
    mem.view(server_addr).setUint32(4, 0, false)  // INADDR_ANY (0.0.0.0)

    var ret = bind_sys(server_fd, server_addr, 16)
    if (ret instanceof BigInt && ret.lo !== 0 && ret.hi !== 0xFFFFFFFF) {
      throw new Error('bind() failed')
    }

    // Get the actual port that was bound using getsockname
    var actual_addr = mem.malloc(16)
    var addrlen = mem.malloc(4)
    mem.view(addrlen).setUint32(0, 16, true)

    ret = getsockname_sys(server_fd, actual_addr, addrlen)
    if (ret instanceof BigInt && ret.lo !== 0 && ret.hi !== 0xFFFFFFFF) {
      throw new Error('getsockname() failed')
    }

    // Read port in network byte order (big-endian) at offset 2
    var actual_port = mem.view(actual_addr).getUint16(2, false)  // big-endian

    // Listen
    ret = listen_sys(server_fd, MAX_CLIENTS)
    if (ret instanceof BigInt && ret.lo !== 0 && ret.hi !== 0xFFFFFFFF) {
      throw new Error('listen() failed')
    }

    // Get server IP from sockaddr
    var ip_addr = mem.view(actual_addr).getUint32(4, false)  // big-endian at offset 4
    var ip_bytes = [
      (ip_addr >> 24) & 0xFF,
      (ip_addr >> 16) & 0xFF,
      (ip_addr >> 8) & 0xFF,
      ip_addr & 0xFF
    ]
    var ip_str = ip_bytes[0] + '.' + ip_bytes[1] + '.' + ip_bytes[2] + '.' + ip_bytes[3]

    // Send notification with IP and port
    utils.notify('FTP: ' + ip_str + ':' + actual_port)

    // Accept loop
    var client_num = 0
    while (true) {
      var client_ret = accept_sys(server_fd, 0, 0)
      var client_fd = client_ret instanceof BigInt ? client_ret.lo : client_ret

      if (client_fd < 0) {
        continue
      }

      client_num++
      handle_client(client_fd, client_num)
    }

  } catch (e) {
    utils.notify('FTP Error: ' + e.message)
  }
}

// Start the server
start_ftp_server()
