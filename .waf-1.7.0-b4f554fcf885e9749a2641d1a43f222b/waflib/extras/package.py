#! /usr/bin/env python
# encoding: utf-8
# WARNING! Do not edit! http://waf.googlecode.com/git/docs/wafbook/single.html#_obtaining_the_waf_file

from waflib import Logs
from waflib.Configure import conf
try:
	from urllib import request
except:
	from urllib import urlopen
else:
	urlopen=request.urlopen
CACHEVAR='WAFCACHE_PACKAGE'
@conf
def get_package_cache_dir(self):
	cache=None
	if CACHEVAR in conf.environ:
		cache=conf.environ[CACHEVAR]
		cache=self.root.make_node(cache)
	elif self.env[CACHEVAR]:
		cache=self.env[CACHEVAR]
		cache=self.root.make_node(cache)
	else:
		cache=self.srcnode.make_node('.wafcache_package')
	cache.mkdir()
	return cache
@conf
def download_archive(self,src,dst):
	for x in self.env.PACKAGE_REPO:
		url='/'.join((x,src))
		try:
			web=urlopen(url)
			try:
				if web.getcode()!=200:
					continue
			except AttributeError:
				pass
		except Exception:
			continue
		else:
			tmp=self.root.make_node(dst)
			tmp.write(web.read())
			Logs.warn('Downloaded %s from %s'%(tmp.abspath(),url))
			break
	else:
		self.fatal('Could not get the package %s'%src)
@conf
def load_packages(self):
	cache=self.get_package_cache_dir()
