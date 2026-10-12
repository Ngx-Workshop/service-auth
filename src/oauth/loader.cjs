// Preserve native ESM import across the CommonJS Nest build.
module.exports = (url) => import(url);
