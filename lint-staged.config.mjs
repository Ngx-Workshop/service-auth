import { getFileInfo } from 'prettier';

export default {
  '*.{ts,js,cjs,mjs,json,md,yml,yaml}': async (files) => {
    const supported = [];
    for (const file of files) {
      const info = await getFileInfo(file, { ignorePath: '.prettierignore' });
      if (!info.ignored && info.inferredParser) supported.push(file);
    }
    return supported.length
      ? `prettier --write ${supported.map((file) => JSON.stringify(file)).join(' ')}`
      : [];
  },
};
