// Read-only module/export snapshot. No hooks, memory writes, or protection changes.
rpc.exports = {
  snapshot(moduleFilter, includeExports, limit) {
    const needle = (moduleFilter || '').toLowerCase();
    const modules = Process.enumerateModules().filter(m => !needle || m.name.toLowerCase().includes(needle));
    let remaining = limit;
    return {
      pid: Process.id,
      architecture: Process.arch,
      pointerSize: Process.pointerSize,
      modules: modules.map(m => {
        const item = {name: m.name, path: m.path, base: m.base.toString(), size: m.size};
        if (includeExports) {
          const symbols = m.enumerateExports();
          item.exports = symbols.slice(0, remaining).map(e => ({name: e.name, type: e.type, address: e.address.toString(), offset: e.address.sub(m.base).toString()}));
          item.exportsTruncated = symbols.length > item.exports.length;
          remaining -= item.exports.length;
        }
        return item;
      })
    };
  }
};
