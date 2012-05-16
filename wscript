# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

VERSION='0.0.1'
LIBNAME='vkey'

def options(opt):
    opt.add_option('--with-debug',action='store_true',default=False,dest='with_debug',help='''Debugging mode''')
    opt.add_option('--with-tests',action='store_true',default=False,dest='with_tests',help='''Build tests (which require boost support)''')
    #opt.add_option('--log4cxx',action='store_true',default=False,dest='log4cxx',help='''Compile with log4cxx support''')
    opt.load('compiler_c')
    opt.load('compiler_cxx')
    opt.load('boost')
    opt.load('ccnx sqlite3', tooldir=["waf-tools"])

def configure(conf):
    conf.load("compiler_cxx")
    conf.env.append_value('CXXFLAGS', ['-O0', '-g3'])

    if not conf.check_cfg(package='openssl', args=['--cflags', '--libs'], uselib_store='SSL', mandatory=False):
      libcrypto = conf.check_cc(lib='crypto',
                                header_name='openssl/crypto.h',
                                define_name='HAVE_SSL',
                                uselib_store='SSL')
    if not conf.get_define ("HAVE_SSL"):
        conf.fatal ("Cannot find SSL libraries")

    conf.load('ccnx sqlite3')
    conf.check_ccnx (path=conf.options.ccnx_dir)
    conf.check_sqlite3 (path=conf.options.sqlite3_dir)

    if conf.options.with_debug:
        conf.define ('_DEBUG', 1)
    
    if conf.options.with_tests:
        conf.load('boost')
        conf.check_boost(lib='system iostreams test thread')
        conf.define ('_TESTS', 1)

    #if conf.options.log4cxx:
        #conf.check_cfg(package='liblog4cxx', args=['--cflags', '--libs'], uselib_store='LOG4CXX', mandatory=True)
                   
def build (bld):
    libvkey = bld.shlib (target=LIBNAME, 
                         features=['cxx', 'cxxshlib'],
                         source = bld.path.ant_glob(['src/*.cpp',
                                                     'src/*.c']),
                         use = 'SSL SQLITE3 CCNX')
                         #use = 'BOOST BOOST_IOSTREAMS BOOST_THREAD SSL TINYXML CCNX')

    # Unit tests
    if bld.get_define('_TESTS'):
        unittests = bld.program (target="tests",
                             source = bld.path.ant_glob(['tests/*.cpp']),
                             features=['cxx', 'cxxprogram'],
                             use = 'BOOST_TEST vkey')

    #if bld.get_define ("HAVE_LOG4CXX"):
    #    libvkey.use += ' LOG4CXX'
    #    unittests.use += ' LOG4CXX'

