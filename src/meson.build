config = configuration_data()
config.set('version', meson.project_version())
configure_file(
    input: 'config.h.in',
    output: 'config.h',
    configuration: config
)

executable(
    'chainsaw-whitelist',
    sources: ['whitelist-main.c', 'syscalls.c'],
    install: true
)

executable(
    'chainsaw-blacklist',
    sources: ['blacklist-main.c'],
    install: true
)

executable(
    'chainsaw-diff',
    sources: ['diff-main.cc'],
    install: true
)

executable(
    'chainsaw-cut',
    sources: ['cut-main.cc'],
    install: true
)
