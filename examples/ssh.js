/*	Copyright 2015-2018 Rivoreo

	Permission is hereby granted, free of charge, to any person obtaining
	a copy of this software and associated documentation files (the
	"Software"), to deal in the Software without restriction, including
	without limitation the rights to use, copy, modify, merge, publish,
	distribute, sublicense, and/or sell copies of the Software, and to
	permit persons to whom the Software is furnished to do so, subject to
	the following conditions:

	The above copyright notice and this permission notice shall be
	included in all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
	EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
	MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
	NONINFRINGEMENT. IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE
	FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
	CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
	WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

var fs = require("fs");
var util = require("util");
var ssh = require("ssh2");
//var tty = require("tty");
var readline = require("readline");
var ALGORITHMS = require("ssh2-streams").constants.ALGORITHMS;
var path = require("path");

var StringStartsWith = function(s, sub) {
	if(s.length < sub.length) return false;
	for(var i=0; i<sub.length; i++) {
		if(s[i] != sub[i]) return false;
	}
	return true;
};

var print_usage = function(name) {
	process.stderr.write(util.format("Usage: %s [<options>] <host> [<command>]\n", name));
};

var program_name = path.basename(process.argv[1]);

var kex_list = ALGORITHMS.SUPPORTED_KEX;
var host = null;
var port = 22;
var user = process.env.USER || process.env.LOGNAME;
if(user === null) {
	process.stderr.write("Cannot get username\n");
	process.exit(1);
}
var host_key_hash = "md5";
var use_tty = -1;
var command = null;
var verbose = 0;
var home = process.env.HOME || process.env.PROFILE;
if(home === null) {
	process.stderr.write("HOME not set\n");
	process.exit(1);
}
var app_home = home + "/.ssh";
var known_hosts_file = app_home + "/known_hosts.js";

var fatal_option_require_argument = function(o) {
	process.stderr.write(util.format("%s: Option '-%s' requires an argument\n", program_name, o));
	process.exit(-1);
};
var end_of_options = false;
for(var i=2; i<process.argv.length; i++) {
	if(!end_of_options && process.argv[i][0] == "-") {
		var o = process.argv[i];
		if(o == "--") end_of_options = true;
		else for(var j=1; j<o.length; j++) switch(o[j]) {
			case "1":
				process.stderr.write(util.format("%s: Protocol version 1 is not supported\n", program_name));
				process.exit(1);
			case "2":
				break;
			case "p":
				if(++i >= process.argv.length) fatal_option_require_argument("p");
				port = Number(process.argv[i]);
				break;
			case "l":
				if(++i >= process.argv.length) fatal_option_require_argument("l");
				user = process.argv[i];
				break;
			case "t":
				if(use_tty === -1) use_tty = 1;
				else use_tty++;
				break;
			case "T":
				use_tty = 0;
				break;
			case "v":
				verbose++;
				break;
			case "a":
				break;
			case "A":
				process.stderr.write(util.format("%s: agent forwarding is currently not supported\n", program_name));
				break;
			case "x":
				break;
			case "X":
				process.stderr.write(util.format("%s: X11 forwarding is currently not supported\n", program_name));
				break;
			default:
				process.stderr.write(util.format("%s: Invalid option '-%s'\n", program_name, o[j]));
				process.exit(-1);
		}
	} else if(host === null) {
		var host = process.argv[i];
		var at_i = host.lastIndexOf("@");
		if(at_i !== -1) {
			user = host.substring(0, at_i);
			host = host.substring(at_i + 1);
		}
	} else {
		command = process.argv.slice(i);
		break;
	}
}

if(host === null) {
	print_usage(program_name);
	process.exit(-1);
}

if(use_tty === -1) use_tty = command === null ? 1 : 0;
if(use_tty === 1 && !process.stdin.isTTY) use_tty = 0;

var connection = new ssh.Client();
connection.on("ready", function() {
	//console.log("SSH client ready");
	//if(use_tty > 1 || (process.stdin.isTTY && use_tty)) process.stdin.setRawMode(true);
	var window = null;
	if(use_tty) {
		window = {
			cols:process.stdout.columns,
			rows:process.stdout.rows,
			term:process.env.TERM
		};
		process.stdin.setRawMode(true);
	}
	var options = { pty:window };
	console.log(options);
	var channel_callback = function(e, stream) {
		if(e) throw e;
		//console.log(stream);
		stream.on("close", function(status, signal) {
			process.stderr.write("SSH stream closed\n");
			connection.end();
			if(use_tty && process.stdin.isTTY) process.stdin.setRawMode(false);
			process.exit(signal ? signal + 128 : status);
		});
		stream.pipe(process.stdout);
		stream.stderr.pipe(process.stderr);
		process.stdin.pipe(stream);
	};
	if(command === null) connection.shell(window, options, channel_callback);
	else connection.exec(command.join(" "), options, channel_callback);
});

var password = process.stdin.isTTY ? function() {
	const BACKSPACE = 127;
	//process.stderr.write("Password: ");
	process.stderr.write(util.format("Password for %s@%s:%d: ", user, host, port));
	process.stdin.setRawMode(true);
	var buffer = new Buffer(256);
	var i = 0;
	var fd = process.stdin.fd;
	do {
		try {
			if(fs.readSync(fd, buffer, i, 1, 0) < 1) break;//return buffer.toString("utf-8", 0, i);
		} catch(e) {
			//console.log(e);
			if(e.code !== "EAGAIN") throw e;
			fd = fs.openSync("/dev/tty", "rs");
			continue;
			//i--;
		}
		//if(i >= 0) console.log("buffer[%d] = %d, buffer = \"%s\"", i, buffer[i], buffer.toString("utf-8", 0, i));
		var c = buffer[i];
		if(c === 0xd || c === 0xa) break;
		if(c === 0x3) {
			if(fd !== process.stdin) fs.closeSync(fd);
			process.stdin.setRawMode(false);
			process.stderr.write("\n");
			process.exit(1);
		}
		if(c !== BACKSPACE) i++;
		else if(i > 0) i--;
	} while(i < 256);
	//console.log("buffer: \"%s\"", buffer.toString("utf-8", 0, i));
	if(fd !== process.stdin) fs.closeSync(fd);
	process.stdin.setRawMode(false);
	process.stderr.write("\n");
	return buffer.toString("utf-8", 0, i);
} : null;

var check_host_key = function(fingerprint, callback) {
	var known_hosts = [];
	var check_known_hosts = function() {
		//console.log(known_hosts);
		for(var i=0; i<known_hosts.length; i++) {
			var item = known_hosts[i];
			if(item.host != host) continue;
			if(item.port != port) continue;
			if(item.hash_type != host_key_hash) continue;
			if(item.fingerprint == fingerprint) callback(true);
			else {
				process.stderr.write("Warning: the host key %s finderprint for the remote host %s:%d has changed from\n%s to %s.\nHost key verification failed.\n");
				callback(false);
			}
			return;
		};
		if(!process.stdin.isTTY) {
			callback(false);
			return;
		}
		var readline_stdio = readline.createInterface({ input:process.stdin, output:process.stderr });
		//process.stderr.write(util.format("The host key for %s:%d is %s, continue? ", host, port, hashed_key));
		readline_stdio.question(util.format("The host key %s fingerprint for %s:%d is %s, continue? ", host_key_hash, host, port, fingerprint), function(answer) {
			readline_stdio.close();
			answer = answer.toLowerCase();
			//callback(StringStartsWith(answer, "yes") || StringStartsWith(answer, "是") || StringStartsWith(answer, "好"));
			var ok = StringStartsWith(answer, "yes") || StringStartsWith(answer, "是") || StringStartsWith(answer, "好") || answer == "y" || answer == "可以";
			if(!ok) {
				callback(ok);
				return;
			}
			var known_host_item = {
				host:host,
				port:port,
				hash_type:host_key_hash,
				fingerprint:fingerprint
			};
			fs.appendFile(known_hosts_file, JSON.stringify(known_host_item) + "\n", { encoding:"utf-8", mode:0640 }, function(e) {
				if(e) process.stderr.write(e.toString());
				else process.stderr.write(util.format("Added host %s:%d to the list of known hosts.", host, port));
				process.stderr.write("\n");
				callback(ok);
			});
		});
	};
	var stream = fs.createReadStream(known_hosts_file, { encoding:"utf-8" });
	stream.on("error", function(e) {
		if(e.code != "ENOENT") {
			process.stderr.write(e.toString());
			process.stderr.write("\n");
		}
		check_known_hosts();
	});
	var incomplete_data = "";
	stream.on("data", function(chunk) {
		incomplete_data += chunk.toString();
		var i, last_i = 0;
		while((i = incomplete_data.indexOf("\n", last_i)) != -1) {
			var line = incomplete_data.substring(last_i, i);
			last_i = i + 1;
			try {
				known_hosts.push(JSON.parse(line));
                        } catch(e) {
				process.stderr.write(e.stack);
				process.stderr.write("\n");
				callback(false);
				return;
			}
		}
	});
	stream.on("end", check_known_hosts);
};

var debug_print = verbose ? function(s) {
	if(verbose < 2 && StringStartsWith(s, "DEBUG: Parser: ")) return;
	process.stderr.write(s);
	process.stderr.write("\n");
} : null;

connection.connect({
	algorithms:{ kex:kex_list },
	host:host,
	port:port,
	username:user,
	password:password,
	hostHash:host_key_hash,
	hostVerifier:check_host_key,
	debug:debug_print
});

