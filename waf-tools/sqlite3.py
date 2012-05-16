#! /usr/bin/env python
# encoding: utf-8

'''

When using this tool, the wscript will look like:

	def options(opt):
	        opt.tool_options('sqlite3', tooldir=["waf-tools"])

	def configure(conf):
		conf.load('compiler_cxx sqlite3')

	def build(bld):
		bld(source='main.cpp', target='app', use='SQLITE3')

Options are generated, in order to specify the location of sqlite3 includes/libraries.


'''
import sys
import re
from waflib import Utils,Logs,Errors
from waflib.Configure import conf
SQLITE3_DIR=['/usr','/usr/local','/opt/local','/sw']
SQLITE3_VERSION_FILE='sqlite3.h'
SQLITE3_VERSION_CODE='''
#include <iostream>
#include <sqlite3.h>
int main() { std::cout << SQLITE_VERSION; }
'''

def options(opt):
	opt.add_option('--sqlite3',type='string',default='',dest='sqlite3_dir',help='''path to where sqlite3 is installed, e.g. /usr/local''')
@conf
def __sqlite3_get_version_file(self,dir):
	try:
		return self.root.find_dir(dir).find_node('%s/%s' % ('include', SQLITE3_VERSION_FILE))
	except:
		return None
@conf
def sqlite3_get_version(self,dir):
	val=self.check_cxx(fragment=SQLITE3_VERSION_CODE,includes=['%s/%s' % (dir, 'include')], execute=True, define_ret = True, mandatory=True)
	return val
@conf
def sqlite3_get_root(self,*k,**kw):
	root=k and k[0]or kw.get('path',None)
	# Logs.pprint ('RED', '   %s' %root)
	if root and self.__sqlite3_get_version_file(root):
		return root
	for dir in SQLITE3_DIR:
		if self.__sqlite3_get_version_file(dir):
			return dir
	if root:
		self.fatal('sqlite3 not found in %s'%root)
	else:
		self.fatal('sqlite3 not found, please provide a --sqlite3 argument (see help)')
@conf
def check_sqlite3(self,*k,**kw):
	if not self.env['CXX']:
		self.fatal('load a c++ compiler first, conf.load("compiler_cxx")')

	var=kw.get('uselib_store','SQLITE3')
	self.start_msg('Checking sqlite3')
	root = self.sqlite3_get_root(*k,**kw);
	self.env.SQLITE3_VERSION=self.sqlite3_get_version(root)

	self.env['INCLUDES_%s'%var]= '%s/%s' % (root, "include");
	self.env['LIB_%s'%var] = "sqlite3"
	self.env['LIBPATH_%s'%var] = '%s/%s' % (root, "lib")

	self.end_msg(self.env.SQLITE3_VERSION)
	if Logs.verbose:
		Logs.pprint('CYAN','	sqlite3 include : %s'%self.env['INCLUDES_%s'%var])
		Logs.pprint('CYAN','	sqlite3 lib     : %s'%self.env['LIB_%s'%var])
		Logs.pprint('CYAN','	sqlite3 libpath : %s'%self.env['LIBPATH_%s'%var])
