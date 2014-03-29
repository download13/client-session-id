var crypto = require('crypto');
var cookie = require('cookie');

var HMAC_ALGORITHM = 'sha1'; // Fast. Change later if better security needed

function base64urlencode(s) {
	s = s.split('=')[0]; // Remove any trailing '='s
	s = s.replace(/\+/g, '-'); // 62nd char of encoding
	s = s.replace(/\//g, '_'); // 63rd char of encoding
	return s;
}

function sign(key, id, expires) {
	var exp = expires.toString(16);
	var h = crypto.createHmac(HMAC_ALGORITHM, key);
	h.update(exp);
	h.update(id);
	var sig = base64urlencode(h.digest('base64'));
	return sig + '|' + exp + '|' + id;
}

function verify(key, data) {
	data = data.split('|');
	var signature = data[0];
	var expires = parseInt(data[1], 16);
	if(isNaN(expires) || expires >= Date.now()) return null;
	var id = data[2];
	var h = crypto.createHmac(HMAC_ALGORITHM);
	h.update(data[1]);
	h.update(id);
	var hash = base64urlencode(h.digest('base64'));
	if(hash === signature) return id;
	return null;
}

function createSessionManager(opts) {
	var name = opts.name || 'sid';
	var ttl = opts.ttl || 7 * 24 * 60 * 60 * 1000; // 7 days by default
	var signLocal = sign.bind(opts.secret);
	var verifyLocal = verify.bind(opts.secret);

	var create = function(id) {
		var expires = Date.now() + ttl;
		var data = signLocal(id, expires);
		setCookie(this, name, data, expires);
	}
	var destroy = function(id) {
		setCookie(this, name, '', -86400);
	}
	var mw = function(req, res, next) {
		var data = cookie.parse(req.headers.cookie);
		if(data != null) data = data[name];
		if(data != null) {
			req[name] = verifyLocal(data);
		}
		res.createSession = create;
		res.destroySession = destroy;

		next();
	}
	
	return mw;
}

function setCookie(res, name, val, expires) {
	var h = res.getHeader('Set-Cookie'); // Don't stomp on other cookies
	if(h == null) h = [];
	else if(typeof h == 'string') h = [h];
	h.push(cookie.serialize(name, val, {expires: expires, path: '/', httpOnly: true}));
	res.setHeader('Set-Cookie', h);
}


module.exports = createSessionManager;
