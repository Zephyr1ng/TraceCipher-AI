(function (_0xroot) {
  var _0x4a = [
    "password",
    "username",
    "payload",
    "meta",
    "version",
    "v3",
    "nonce",
    "source",
    "web",
    "url",
    "base64",
    "buildLoginPayload",
    "submitLogin",
    "encodeURIComponent",
    "btoa",
    "fromCharCode",
    "charCodeAt",
    "split",
    "reverse",
    "join",
    "length",
    "push",
    "apply",
    "call",
    "now",
    "Date",
    "random",
    "Math",
    "toString",
    "slice",
    "login",
    "/api/auth/login",
    "headers",
    "Content-Type",
    "application/json",
    "body",
    "POST",
    "method",
    "JSON",
    "stringify"
  ];

  function _0x2f(_0xidx) {
    return _0x4a[_0xidx];
  }

  function _0x7b(_0xvalue) {
    return String(_0xvalue == null ? "" : _0xvalue);
  }

  function _0x21(_0xtext) {
    var _0xbag = [];
    var _0xseed = [117, 114, 108];
    var _0xmark = [98, 97, 115, 101, 54, 52];
    _0xbag[_0x21[_0x2f(20)] || 0] = String[_0x2f(15)][_0x2f(22)](null, _0xseed);
    _0xbag[_0x2f(21)](String[_0x2f(15)][_0x2f(22)](null, _0xmark));
    _0x21[_0x2f(20)] = _0xbag[_0x2f(20)];
    return _0xbag;
  }

  function _0x8c(_0xinput) {
    var _0xfn = _0x2f(13);
    return _0xroot[_0xfn](_0x7b(_0xinput));
  }

  function _0x5e(_0xinput) {
    var _0xname = _0x2f(14);
    if (typeof _0xroot[_0xname] === "function") {
      return _0xroot[_0xname](_0xinput);
    }
    if (typeof Buffer !== "undefined") {
      return Buffer.from(_0xinput, "utf-8").toString(_0x2f(10));
    }
    throw new Error("Base64 encoder unavailable");
  }

  function _0x91(_0xvalue) {
    var _0xstack = _0x21(_0xvalue);
    var _0xurl = _0x8c(_0xvalue);
    var _0xenc = _0x5e(_0xurl);
    return {
      flow: _0xstack,
      result: _0xenc
    };
  }

  function _0x63(_0xinput) {
    var _0xchars = _0x7b(_0xinput)[_0x2f(17)]("");
    var _0xmix = _0xchars[_0x2f(18)]()[_0x2f(18)]()[_0x2f(19)]("");
    return _0x91(_0xmix).result;
  }

  function _0x76() {
    return (
      _0x2f(30) +
      "-" +
      _0xroot[_0x2f(25)][_0x2f(24)]()[_0x2f(28)](16)[_0x2f(29)](-6) +
      "-" +
      _0xroot[_0x2f(27)][_0x2f(26)]()[_0x2f(28)](16)[_0x2f(29)](2, 8)
    );
  }

  function _0x55(_0xuser, _0xpassword) {
    var _0xpwField = _0x2f(0);
    var _0xuserField = _0x2f(1);
    var _0xdata = {};
    _0xdata[_0xuserField] = _0x7b(_0xuser);
    _0xdata[_0xpwField] = _0x63(_0xpassword);
    _0xdata[_0x2f(3)] = {
      channel: _0x2f(8),
      stage: _0x2f(9),
      trace: _0x76()
    };
    _0xdata[_0x2f(4)] = _0x2f(5);
    return _0xdata;
  }

  function _0x4d(_0xuser, _0xpassword) {
    var _0xpacket = _0x55(_0xuser, _0xpassword);
    return {
      url: _0x2f(31),
      options: {
        [_0x2f(37)]: _0x2f(36),
        [_0x2f(32)]: {
          [_0x2f(33)]: _0x2f(34)
        },
        [_0x2f(35)]: _0xroot[_0x2f(38)][_0x2f(39)](_0xpacket)
      }
    };
  }

  _0xroot[_0x2f(11)] = _0x55;
  _0xroot[_0x2f(12)] = _0x4d;
})(typeof window !== "undefined" ? window : globalThis);
