var O_RDONLY = 0;
var O_LARGEFILE = 32768;
var SEEK_SET = 0;
var SEEK_CUR = 1;
var SEEK_END = 2;

function allocStr(str) {
    return Memory.allocUtf8String(str);
}

function getStr(addr) {
	if (typeof(addr) == 'number') {
		addr = ptr(addr);
	}
	return Memory.readUtf8String(addr);
}

function putStr(addr, str) {
	if (typeof(addr) == 'number') {
		addr = ptr(addr);
	}
	return Memory.writeUtf8String(addr, str);
}

function getByteArr(addr, l) {
	if (typeof(addr) == 'number') {
		addr = ptr(addr);
	}
	return Memory.readByteArray(addr, l);
}

function getU8(addr) {
	if (typeof(addr) == 'number') {
		addr = ptr(addr);
	}
	return Memory.readU8(addr);
}

function putU8(addr, n) {
	if (typeof(addr) == 'number') {
		addr = ptr(addr);
	}
	return Memory.writeU8(addr, n);
}

function getU16(addr) {
	if (typeof(addr) == 'number') {
		addr = ptr(addr);
	}
	return Memory.readU16(addr);
}

function putU16(addr, n) {
	if (typeof(addr) == 'number') {
		addr = ptr(addr);
	}
	return Memory.writeU16(addr, n);
}

function getU32(addr) {
	if (typeof(addr) == 'number') {
		addr = ptr(addr);
	}
	return Memory.readU32(addr);
}

function putU32(addr, n) {
	if (typeof(addr) == 'number') {
		addr = ptr(addr);
	}
	return Memory.writeU32(addr, n);
}

function getU64(addr) {
	if (typeof(addr) == 'number') {
		addr = ptr(addr);
	}
	return Memory.readU64(addr);
}

function putU64(addr, n) {
	if (typeof(addr) == 'number') {
		addr = ptr(addr);
	}
	return Memory.writeU64(addr, n);
}

function getPt(addr) {
	if (typeof(addr) == 'number') {
		addr = ptr(addr);
	}
	return Memory.readPointer(addr);
}

function putPt(addr, n) {
	if (typeof(addr) == 'number') {
		addr = ptr(addr);
	}
	if (typeof(n) == 'number') {
		n = ptr(n);
	}
	return Memory.writePointer(addr, n);
}

function getExportFunction(type, name, ret, args) {
    var nptr;
    nptr = Module.findExportByName(null, name);
    if (nptr === null) {
        console.log('cannot find ' + name);
        return null;
    }
    else {
        if (type === 'f') {
            var funclet = new NativeFunction(nptr, ret, args);
            if (typeof(funclet) === 'undefined') {
                console.log('parse error ' + name);
                return null;
            }
            return funclet;
        }
        else if (type === 'd') {
            var datalet = Memory.readPointer(nptr);
            if (typeof(datalet) === 'undefined') {
                console.log('parse error ' + name);
                return null;
            }
            return datalet;
        }
    }
}

function dumpMemory(addr, length) {
	console.log(hexdump(Memory.readByteArray(addr, length), {
		offset: 0,
		length: length,
		header: true,
		ansi: true
	}));
}

wrapper_open = getExportFunction('f', 'open', 'int', ['pointer', 'int']);
read = getExportFunction('f', 'read', 'int', ['int', 'pointer', 'int']);
lseek = getExportFunction('f', 'lseek', 'int', ['int', 'int', 'int']);
close = getExportFunction('f', 'close', 'int', ['int']);
dladdr = getExportFunction('f', 'dladdr', 'int', ['pointer', 'pointer']);
wrapper_sscanf = getExportFunction('f', 'sscanf', 'int', ['pointer', 'pointer', 'pointer', 
					'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer',
					'pointer', 'pointer', 'pointer']);
getpid = getExportFunction('f', 'getpid', 'int', []);
			
function getProcessName() {
	var fd = open("/proc/" + getpid() + "/cmdline");
	if (fd == -1) {
		return "unknown";
	}
	var buffer = malloc(32);
	read(fd, buffer, 32);
	close(fd);
	return getStr(buffer);
}
			
function open(pathname, flags) {
	if (typeof(pathname) == "string") {
		pathname = allocStr(pathname);
	}
	return wrapper_open(pathname, O_RDONLY);
}

function getFileSize(fd) {
	return lseek(fd, 0, SEEK_END);
}

function malloc(size) {
	return Memory.alloc(size);
}

function memcpy(dst, src, n) {
	return Memory.copy(dst, src, n);
}

function sscanf(buffer, format, np1, np2, np3, np4, np5, np6, np7, np8, np9, np10, np11) {
	if (typeof(format) == "string") {
		format = allocStr(format);
	}
	return wrapper_sscanf(buffer, format, np1, np2, np3, np4, np5, np6, np7, np8, np9, np10, np11);
}

function getSymbol(addr) {
	if (addr == 0) {
		return new Object();
	}
	var dlinfo = malloc(32);
	var npaddr = ptr(addr);
	putU64(dlinfo.add(0), 0);
	putU64(dlinfo.add(8), 0);
	putU64(dlinfo.add(16), 0);
	putU64(dlinfo.add(24), 0);
	dladdr(npaddr, dlinfo);
	var sym = new Object();
	if (Process.pointerSize == 4) {
		libnameptr = getPt(dlinfo.add(0));
		if (libnameptr.isNull()) {
			sym.libname = "unknown";
		}
		else {
			sym.libname = getStr(libnameptr);
		}
		funcnameptr = getPt(dlinfo.add(8));
		if (funcnameptr.isNull()) {
			sym.funcname = "unknown";
		}
		else {
			sym.funcname = getStr(funcnameptr);
		}
		sym.libbase = getU32(dlinfo.add(4));
		sym.funcoff = npaddr.sub(getPt(dlinfo.add(12)));
	}
	else {
		libnameptr = getPt(dlinfo.add(0));
		if (libnameptr.isNull()) {
			sym.libname = "unknown";
		}
		else {
			sym.libname = getStr(libnameptr);
		}
		funcnameptr = getPt(dlinfo.add(16));
		if (funcnameptr.isNull()) {
			sym.funcname = "unknown";
		}
		else {
			sym.funcname = getStr(funcnameptr);
		}
		sym.libbase = getU64(dlinfo.add(8));
		sym.funcoff = npaddr.sub(getPt(dlinfo.add(24)));
	}
	if (sym.libname == "unknown" || sym.funcname == "unknown") {
		for (var i = global_symbols.length - 1; i >= 0; i--) {
			if (addr >= global_symbols[i].address ) {
				sym.libname = global_symbols[i].path;
				sym.funcname = global_symbols[i].name
				sym.funcoff = addr - global_symbols[i].address;
				break;
			}
		}
	}
	return sym;
}

function readSmallFile(filepath) {
	var fd = open(filepath, O_RDONLY);
	if (fd == -1) {
		return "";
	}
	var buffersize = 0x1000000;
	var buffer = malloc(buffersize);
	lseek(fd, 0, SEEK_SET);
	read(fd, buffer, buffersize);
	close(fd);
	return getStr(buffer);
}

function getAllModules() {
	var modulelines = readSmallFile("/proc/self/maps").split("\n");
	var modules = new Array();
	var buffer = malloc(512);
	for (var i = 0; i < modulelines.length; i++) { 
		putStr(buffer.add(256), modulelines[i]);
		putU64(buffer.add(0), 0); // begin address
		putU64(buffer.add(8), 0); // end address
		putU64(buffer.add(16), 0); // permission
		putU64(buffer.add(24), 0); // pgoff
		putU64(buffer.add(32), 0); // major
		putU64(buffer.add(40), 0); // minor
		putU64(buffer.add(48), 0); // ino
		putU64(buffer.add(56), 0); // path
		sscanf(buffer.add(256), "%lx-%lx %c%c%c%c %llx %x:%x %lu %s", 
					buffer.add(0), buffer.add(8), buffer.add(16), buffer.add(17), buffer.add(18),
					buffer.add(19), buffer.add(24), buffer.add(32), buffer.add(40), 
					buffer.add(48), buffer.add(56));
		var vmmin = getU64(buffer.add(0));
		var vmmax = getU64(buffer.add(8));
		var path = getStr(buffer.add(56));
		if (path[0] != '/') {
			continue;
		}
		// Check exist
		var exist = false;
		for (var j = 0; j < modules.length; j++) {
			if (modules[j].path == path) {
				if (modules[j].vmmin > vmmin) {
					modules[j].vmmin = vmmin;
				}
				if (modules[j].vmmax < vmmax) {
					modules[j].vmmax = vmmax;
				}
				exist = true;
				break;
			}
		}
		if (!exist) {
			var module = new Object();
			module.vmmin = vmmin;
			module.vmmax = vmmax;
			module.path = path;
			modules.push(module);
		}
	}
	return modules;
}

// Export function: get all loaded module info
function checkAllModules() {
	var modules = getAllModules();
	for (var i = 0; i < modules.length; i++) {
		console.log("start:" + modules[i].vmmin.toString(16) + " end:" + 
			modules[i].vmmax.toString(16) + " path:" + modules[i].path);
	}
}

function getElfData(module) {
	var fd = open(module.path, O_RDONLY);
	if (fd == -1) {
		return false;
	}
	// Read elf header
	var size_of_Elf32_Ehdr = 52;
	var off_of_Elf32_Ehdr_phoff = 28; 		// 4
	var off_of_Elf32_Ehdr_shoff = 32; 		// 4
	var off_of_Elf32_Ehdr_phentsize = 42;	// 2
	var off_of_Elf32_Ehdr_phnum = 44; 		// 2
	var off_of_Elf32_Ehdr_shentsize = 46; 	// 2
	var off_of_Elf32_Ehdr_shnum = 48; 		// 2
	var off_of_Elf32_Ehdr_shstrndx = 50; 	// 2
	var size_of_Elf64_Ehdr = 64;
	var off_of_Elf64_Ehdr_phoff = 32;		// 8
	var off_of_Elf64_Ehdr_shoff = 40;		// 8
	var off_of_Elf64_Ehdr_phentsize = 54;	// 2
	var off_of_Elf64_Ehdr_phnum = 56;		// 2
	var off_of_Elf64_Ehdr_shentsize = 58;	// 2
	var off_of_Elf64_Ehdr_shnum = 60;		// 2
	var off_of_Elf64_Ehdr_shstrndx = 62;	// 2
	// Parse Ehdr
	var ehdr = malloc(64);
	lseek(fd, 0, SEEK_SET);
	read(fd, ehdr, 64);
	var is32bit = getU8(ehdr.add(4)) != 2; // 1:32 2:64
	if (is32bit) {
		var phoff = 	getU32(ehdr.add(off_of_Elf32_Ehdr_phoff));
		var shoff = 	getU32(ehdr.add(off_of_Elf32_Ehdr_shoff));
		var phentsize = getU16(ehdr.add(off_of_Elf32_Ehdr_phentsize));
		var phnum = 	getU16(ehdr.add(off_of_Elf32_Ehdr_phnum));
		var shentsize = getU16(ehdr.add(off_of_Elf32_Ehdr_shentsize));
		var shnum = 	getU16(ehdr.add(off_of_Elf32_Ehdr_shnum));
		var shstrndx = 	getU16(ehdr.add(off_of_Elf32_Ehdr_shstrndx));
		var off_of_Elf_Shdr_shname = 0;		// 4
		var off_of_Elf_Shdr_shaddr = 12;	// 4
		var off_of_Elf_Shdr_shoffset = 16;	// 4
		var off_of_Elf_Shdr_shsize = 20;	// 4
	}
	else {
		var phoff = 	getU64(ehdr.add(off_of_Elf64_Ehdr_phoff));
		var shoff = 	getU64(ehdr.add(off_of_Elf64_Ehdr_shoff));
		var phentsize = getU16(ehdr.add(off_of_Elf64_Ehdr_phentsize));
		var phnum = 	getU16(ehdr.add(off_of_Elf64_Ehdr_phnum));
		var shentsize = getU16(ehdr.add(off_of_Elf64_Ehdr_shentsize));
		var shnum = 	getU16(ehdr.add(off_of_Elf64_Ehdr_shnum));
		var shstrndx = 	getU16(ehdr.add(off_of_Elf64_Ehdr_shstrndx));
		var off_of_Elf_Shdr_shname = 0;		// 4
		var off_of_Elf_Shdr_shaddr = 16;	// 8
		var off_of_Elf_Shdr_shoffset = 24;	// 8
		var off_of_Elf_Shdr_shsize = 28;	// 8
	}
	// Parse Shdr
	var shdrs = malloc(shentsize * shnum);
	lseek(fd, shoff, SEEK_SET);
	read(fd, shdrs, shentsize * shnum);
	if (is32bit) {
		shstr_offset = getU32(shdrs.add(shentsize * shstrndx + off_of_Elf_Shdr_shoffset));
		shstr_size = getU32(shdrs.add(shentsize * shstrndx + off_of_Elf_Shdr_shsize));
	}
	else {
		shstr_offset = getU64(shdrs.add(shentsize * shstrndx + off_of_Elf_Shdr_shoffset));
		shstr_size = getU64(shdrs.add(shentsize * shstrndx + off_of_Elf_Shdr_shsize));
	}
	var str_tbl = malloc(shstr_size);
	lseek(fd, shstr_offset, SEEK_SET);
	read(fd, str_tbl, shstr_size);
	var sections = new Array();
	for (var i = 0; i < shnum; i++) {
		if (is32bit) {
			var shname_off =getU32(shdrs.add(i * shentsize + off_of_Elf_Shdr_shname));
			var shname =	getStr(str_tbl.add(shname_off));
			var shaddr =	getU32(shdrs.add(i * shentsize + off_of_Elf_Shdr_shaddr));
			var shoffset =	getU32(shdrs.add(i * shentsize + off_of_Elf_Shdr_shoffset));
			var shsize =	getU32(shdrs.add(i * shentsize + off_of_Elf_Shdr_shsize));
		}
		else {
			var shname_off =getU32(shdrs.add(i * shentsize + off_of_Elf_Shdr_shname));
			var shname =	getStr(str_tbl.add(shname_off));
			var shaddr =	getU64(shdrs.add(i * shentsize + off_of_Elf_Shdr_shaddr));
			var shoffset =	getU64(shdrs.add(i * shentsize + off_of_Elf_Shdr_shoffset));
			var shsize =	getU64(shdrs.add(i * shentsize + off_of_Elf_Shdr_shsize));
		}
		if (shname == ".text" || shname == ".rodata" || shname == ".got" || shname == ".got.plt") {
			// Check item
			var section = new Object();
			section.name = shname;
			section.memaddr = shaddr + module.vmmin;
			section.size = shsize;
			section.data = malloc(shsize);
			lseek(fd, shoffset, SEEK_SET);
			read(fd, section.data, shsize);
			sections.push(section);
		}
		if (shname == ".dynsym" || shname == ".dynstr" || shname == ".rel.dyn" || 
				shname == ".rel.plt") {
			var section = new Object();
			section.size = shsize;
			section.data = malloc(shsize);
			lseek(fd, shoffset, SEEK_SET);
			read(fd, section.data, shsize);
			module[shname] = section;
		}
	}
	module.sections = sections;
	return true;
}

function compareMemory(module, mask) {
	for (var i = 0; i < module.sections.length; i++) {
		section = module.sections[i];
		if (section.name == ".rodata" && (mask & 1) != 0) {
			// Compare directly
			var filedata = new Uint8Array(getByteArr(section.data, section.size));
			var memdata = new Uint8Array(getByteArr(ptr(section.memaddr), section.size));
			for (var j = 0; j < section.size; j++) {
				if (filedata[j] != memdata[j]) {
					console.log(".rodata\taddr:" + (section.memaddr + j).toString(16) + " file-mem:" + 
						filedata[j].toString(16) + "-" + memdata[j].toString(16));
				}
			}
		}
		else if (section.name == ".text" && (mask & 2) != 0) {
			// Compare and get symbol
			var filedata = new Uint8Array(getByteArr(section.data, section.size));
			var memdata = new Uint8Array(getByteArr(ptr(section.memaddr), section.size));
			for (var j = 0; j < section.size; j++) {
				if (filedata[j] != memdata[j]) {
					sym = getSymbol(section.memaddr + j);
					console.log(".text\taddr:" + sym.funcname + "+" + sym.funcoff.toString(16) +
						" file-mem:" +  filedata[j].toString(16) + "-" + memdata[j].toString(16));
					if ((memdata[j] == 0x01 && memdata[j + 1] == 0x00 && memdata[j + 2] == 0x9f && memdata[j + 3] == 0xef) ||
						(memdata[j] == 0xf0 && memdata[j + 1] == 0x01 && memdata[j + 2] == 0xf0 && memdata[j + 3] == 0xe7) ||
						(memdata[j] == 0x01 && memdata[j + 1] == 0xde) ||
						(memdata[j] == 0xf0 && memdata[j + 1] == 0xf7 && memdata[j + 2] == 0x00 && memdata[j + 3] == 0xa0) ||
						(memdata[j] == 0x0d && memdata[j + 1] == 0x00 && memdata[j + 2] == 0x05 && memdata[j + 3] == 0x00) ||
						(memdata[j] == 0x00 && memdata[j + 1] == 0x00 && memdata[j + 2] == 0x20 && memdata[j + 3] == 0xd4) ||
						(memdata[j] == 0xcc)) {
						console.log("software breakpoint detected!!!");
					}
				}
			}
		}
		else if (section.name == ".got" && (mask & 4) != 0) {
			if (Process.pointerSize == 4) {
				var filedata = new Uint32Array(getByteArr(section.data, section.size));
				var memdata = new Uint32Array(getByteArr(ptr(section.memaddr), section.size));
				for (var j = 0; j < section.size / 4; j++) {
					if (filedata[j] + module.vmmin != memdata[j] && memdata[j] != 0 && filedata[j] != 0) {
						var sym = new Object();
						if (memdata[j] != 0) {
							sym = getSymbol(memdata[j]);
						}
						console.log(".got " + j + "/" + (section.size / 4) + "\taddr:" + 
							(section.memaddr + j * 4).toString(16) + " file-mem:" + 
							filedata[j].toString(16) + "-" + memdata[j].toString(16) + 
							" ->" + sym.libname + "." + sym.funcname);
					}
				}
			}
			else {
				var filedata = new Uint32Array(getByteArr(section.data, section.size));
				var memdata = new Uint32Array(getByteArr(ptr(section.memaddr), section.size));
				for (var j = 0; j < section.size / 8; j++) {
					var F = filedata[j * 2] * 0xFFFFFFFF + filedata[j * 2 + 1];
					var M = memdata[j * 2] * 0xFFFFFFFF + memdata[j * 2 + 1];
					if (F + module.vmmin != M && F != 0 && M != 0) {
						var sym = new Object();
						if (M != 0) {
							sym = getSymbol(M);
						}
						console.log(".got " + j + "/" + (section.size / 8) + "\taddr:" + 
							(section.memaddr + j * 8).toString(16) + " file-mem:" + F.toString(16) + 
							"-" + M.toString(16) + " ->" + sym.libname + "." + sym.funcname);
					}
				}
			}
		}
		else if (section.name == ".got.plt" && (mask & 8) != 0) {
			if (Process.pointerSize == 4) {
				var filedata = new Uint32Array(getByteArr(section.data, section.size));
				var memdata = new Uint32Array(getByteArr(ptr(section.memaddr), section.size));
				for (var j = 0; j < section.size / 4; j++) {
					console.log(filedata[j].toString(16) + memdata[j] + toString(16));
					if (filedata[j] + module.vmmin != memdata[j] && memdata[j] != 0 && filedata[j] != 0) {
						var sym = new Object();
						if (memdata[j] != 0) {
							sym = getSymbol(memdata[j]);
						}
						console.log(".got.plt " + j + "/" + (section.size / 4) + "\taddr:" + 
							(section.memaddr + j * 4).toString(16) + " file-mem:" + 
							filedata[j].toString(16) + "-" + memdata[j].toString(16) + " ->" + 
							sym.libname + "." + sym.funcname);
					}
				}
			}
			else {
				var filedata = new Uint32Array(getByteArr(section.data, section.size));
				var memdata = new Uint32Array(getByteArr(ptr(section.memaddr), section.size));
				for (var j = 0; j < section.size / 8; j++) {
					var F = filedata[j * 2] * 0xFFFFFFFF + filedata[j * 2 + 1];
					var M = memdata[j * 2] * 0xFFFFFFFF + memdata[j * 2 + 1];
					if (F + module.vmmin != M && F != 0 && M != 0) {
						var sym = new Object();
						if (M != 0) {
							sym = getSymbol(M);
						}
						console.log(".got.plt " + j + "/" + (section.size / 8) + "\taddr:" + 
							(section.memaddr + j * 8).toString(16) + " file-mem:" +  F.toString(16) + 
							"-" + M.toString(16) + " ->" + sym.libname + "." + sym.funcname);
					}
				}
			}
		}
	}
}

// Export function: check all loaded module consistence with file
/**
	nfilter : null for all modules, "libc.so" for libc.so
	mask : 0x1 for .rodata  0x2 for .text  0x4 for .got  0x8 for .plt.got
*/
var global_symbols = new Array();
function checkConsistency(nfilter, mask) {
	var modules = getAllModules();
	for (var i = 0; i < modules.length; i++) {
		// modules 按地址升序排列 address/name/type
		var modsym = Module.enumerateExportsSync(modules[i].path);
		modsym.sort(function(v1, v2) {
			return v1.address - v2.address;
		});
		for (var j = 0; j < modsym.length; j++) {
			modsym[j].path = modules[i].path;
		}
		global_symbols = global_symbols.concat(modsym);
	}
	
	for (var i = 0; i < modules.length; i++) {
		if (nfilter == null || modules[i].path.indexOf(nfilter) != -1) {
			if(getElfData(modules[i])) {
				compareMemory(modules[i], mask);
			}
		}
	}  
}

// Test case
// ...