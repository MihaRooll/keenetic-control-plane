/** Login page helper — no credential storage. */
(function () {
  "use strict";
  if (typeof localStorage !== "undefined") {
    var keys = Object.keys(localStorage);
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      if (/password|token|cookie|hub_admin/i.test(key)) {
        localStorage.removeItem(key);
      }
    }
  }
})();
