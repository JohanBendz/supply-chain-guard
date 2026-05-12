'use strict';
// Simulated axios-like source file
// Note: mock-unapproved-dep is NEVER imported here.
// It exists in package.json but has zero usage in source.

const followRedirects = require('follow-redirects');
const FormData = require('form-data');
const proxyFromEnv = require('proxy-from-env');

function createInstance() {
  return {
    get: (url) => followRedirects.http.get(url, () => {}),
    post: (url, data) => {
      const form = new FormData();
      const proxy = proxyFromEnv.getProxyForUrl(url);
      return { url, data, proxy };
    }
  };
}

module.exports = createInstance();
