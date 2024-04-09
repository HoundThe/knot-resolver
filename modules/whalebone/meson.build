# C module: whalebone

whalebone_src = files([
  'whalebone.c',
])
c_src_lint += whalebone_src

whalebone_mod = shared_module(
  'whalebone',
  whalebone_src,
  dependencies: [
    libknot,
  ],
  include_directories: mod_inc_dir,
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
  link_with: kresd,
)
