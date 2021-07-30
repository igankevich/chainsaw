project(
    'chainsaw',
    ['c', 'cpp'],
    version: '0.4.1',
    meson_version: '>=0.46',
    default_options: ['c_std=c11', 'cpp_std=c++11'],
    license: 'unlicense'
)

cc = meson.get_compiler('c')
cpp = meson.get_compiler('cpp')

foreach arg : [
    '-Werror=return-type',
    '-Werror=return-local-addr',
    '-Werror=cast-align',
    '-Wcast-align=strict',
    '-Wno-ignored-attributes',
    '-fvisibility-inlines-hidden'
]
	if cc.has_argument(arg)
		add_global_arguments(arg, language: 'c')
	endif
	if cpp.has_argument(arg)
		add_global_arguments(arg, language: 'cpp')
	endif
endforeach

subdir('src')
