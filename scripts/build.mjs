/** Build only the Registry shell and its five client plugins. */
import { build as bundle } from 'esbuild'
import { build as viteBuild } from 'vite'
import { transform } from 'lightningcss'
import { readFileSync } from 'node:fs'
import { dirname, resolve, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const plugins = ['modules', 'ui-renderer', 'locale', 'ui-theme', 'ui-registry']
const external = ['react', 'react/jsx-runtime', 'react-dom', 'react-dom/client', '@deepseek-ai/cordis',
  '@deepseek-ai/dsh-client-store', '@deepseek-ai/dsh-client-ui-slots', '@deepseek-ai/dsh-client-ui-primitives']
const defines = { 'process.env.NODE_ENV': '"production"', 'import.meta.env.MODE': '"production"',
  'import.meta.env': '{"MODE":"production"}' }

function cssPlugin(id) {
  return { name: 'registry-css', setup(build) {
    build.onResolve({ filter: /\.css(?:\?inline)?$/ }, args => ({
      path: resolve(args.resolveDir, args.path.replace(/\?inline$/, '')),
      namespace: args.path.endsWith('?inline') ? 'css-text' : 'css-module',
    }))
    for (const namespace of ['css-text', 'css-module']) build.onLoad({ filter: /.*/, namespace }, args => {
      const result = transform({ filename: relative(root, args.path), code: readFileSync(args.path),
        minify: true, ...(args.path.endsWith('.module.css') ? { cssModules: { pattern: '[hash]_[local]' } } : {}) })
      const css = JSON.stringify(result.code.toString())
      if (namespace === 'css-text') return { contents: `export default ${css}`, loader: 'js' }
      const classes = Object.fromEntries(Object.entries(result.exports ?? {}).map(([key, value]) => [key, value.name]))
      return { contents: `const tag=document.createElement('style');tag.dataset.plugin=${JSON.stringify(id)};tag.textContent=${css};document.head.append(tag);export default ${JSON.stringify(classes)};`, loader: 'js' }
    })
  } }
}

for (const plugin of plugins) {
  const directory = resolve(root, 'packages/client', plugin)
  const manifest = JSON.parse(readFileSync(resolve(directory, 'package.json')))
  await bundle({ absWorkingDir: root, entryPoints: [resolve(directory, 'src/client/index.ts')],
    outfile: resolve(directory, 'lib/client.js'), bundle: true, format: 'cjs', platform: 'browser',
    target: 'es2022', jsx: 'automatic', minify: true, external, define: defines,
    banner: { js: `window.__ModuleLoader__.load({id:${JSON.stringify(manifest.name)},factory:(require)=>{var module={exports:{}};var exports=module.exports;` },
    footer: { js: 'return module.exports;}});' }, plugins: [cssPlugin(manifest.name)] })
  console.log(`Built ${manifest.name}`)
}

await viteBuild({ configFile: false, root: resolve(root, 'apps/web'), base: '/',
  build: { target: 'es2022', sourcemap: false },
  esbuild: { jsx: 'automatic' },
  resolve: { dedupe: ['react','react-dom'], alias: {
    'node:module': resolve(root, 'apps/web/src/node-module-stub.ts'),
  } },
  define: { ...defines, 'process.versions.node': '"0.0.0"', 'process.execArgv': '[]', 'process.env.CORDIS_SHARED': 'undefined' },
})
console.log('Registry build complete. Run npm start.')
