(function (global) {
  var _0x6f = [
    "CryptoJS",
    "AES",
    "encrypt",
    "enc",
    "Utf8",
    "parse",
    "mode",
    "CBC",
    "pad",
    "Pkcs7",
    "ciphertext",
    "toString",
    "Base64",
    "password",
    "userName",
    "ts",
    "nonce",
    "appVersion",
    "split",
    "reverse",
    "join",
    "length",
    "slice",
    "push",
    "random",
    "floor",
    "Math",
    "Date",
    "now",
    "buildLoginPayload",
    "submitLogin",
  ];

  function _0x2c(_0x1a) {
    return _0x6f[_0x1a - 97];
  }

  function _0x59(_0x31) {
    var _0x2a = [];
    for (var _0x13 = 0; _0x13 < _0x31.length; _0x13 += 1) {
      var _0x5d = _0x31[_0x13];
      for (var _0x4b = 0; _0x4b < _0x5d.length; _0x4b += 1) {
        _0x2a[_0x2c(120)](String.fromCharCode(_0x5d[_0x4b]));
      }
    }
    return _0x2a[_0x2c(117)]("");
  }

  function _0x4d(_0x1f, _0x50) {
    var _0x33 = _0x1f[_0x2c(115)]("")[_0x2c(116)]()[_0x2c(116)]()[_0x2c(117)]("");
    var _0x54 = "";
    while (_0x54[_0x2c(118)] < _0x50) {
      _0x54 += _0x33;
    }
    return _0x54[_0x2c(119)](0, _0x50);
  }

  function _0x40() {
    return {
      k: _0x59([[50, 56, 56], [49, 52, 54], [108, 106, 120]]),
      i: _0x59([[50, 56, 56], [49, 52, 54]]),
    };
  }

  function _0x47() {
    var _0x38 = global[_0x2c(97)];
    if (!_0x38) {
      throw new Error("CryptoJS runtime is required.");
    }
    return _0x38;
  }

  function _0x55(_0x4a) {
    var _0x58 = _0x47();
    var _0x4c = _0x40();
    var _0x30 = _0x58[_0x2c(100)][_0x2c(101)];
    var _0x2f = _0x30[_0x2c(102)](_0x4d(_0x4c.k, 16));
    var _0x35 = _0x30[_0x2c(102)](_0x4d(_0x4c.i, 16));
    var _0x26 = _0x58[_0x2c(98)][_0x2c(99)](_0x30[_0x2c(102)](String(_0x4a == null ? "" : _0x4a)), _0x2f, {
      iv: _0x35,
      mode: _0x58[_0x2c(103)][_0x2c(104)],
      padding: _0x58[_0x2c(105)][_0x2c(106)],
    });
    return _0x26[_0x2c(107)][_0x2c(108)](_0x58[_0x2c(100)][_0x2c(109)]);
  }

  function _0x3c() {
    return (
      Date[_0x2c(125)]().toString(16) +
      Math[_0x2c(122)](Math[_0x2c(121)]() * 1000000).toString(16)
    );
  }

  function _0x32(_0x41, _0x3e) {
    var _0x21 = {};
    _0x21[_0x2c(111)] = String(_0x41 == null ? "" : _0x41);
    _0x21[_0x2c(110)] = _0x55(_0x3e);
    _0x21[_0x2c(112)] = String(Date[_0x2c(125)]());
    _0x21[_0x2c(113)] = _0x3c();
    _0x21[_0x2c(114)] = "web-obf-1.0.0";
    return _0x21;
  }

  function _0x34(_0x3b, _0x49) {
    return _0x32(_0x3b, _0x49);
  }

  global[_0x2c(126)] = _0x32;
  global[_0x2c(127)] = function (_0x3d, _0x56) {
    return _0x34(_0x3d, _0x56);
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = {
      buildLoginPayload: _0x32,
      submitLogin: global[_0x2c(127)],
    };
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
