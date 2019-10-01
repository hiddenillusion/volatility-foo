# dllfind was created by Glenn P. Edwards Jr.
#      https://hiddenillusion.github.io
#           @hiddenillusion
#	(while at FireEye)
# Version 0.2.4
# Date: 2013-12-09
# Requirements:
#        - written and tested with Volatility v2.3
# To-Do:
#       [ ] fix unicode issue
#	[x] fix https://code.google.com/p/volatility/source/detail?r=2071

import os
import re
import volatility.debug as debug
import volatility.plugins.taskmods as taskmods

class DllFind(taskmods.DllList):
  """Search for a specific DLL across all processes"""

  def __init__(self, config, *args, **kwargs):
    taskmods.DllList.__init__(self, config, *args, **kwargs)
    config.add_option('DLL', short_option = 'm', default = None,
                      help = 'Name of DLL to search for',
                      action = 'store', type = 'str')

  def render_text(self, outfd, data):
    if self._config.DLL == None:
      debug.error("Please specify a DLL to search for (-m)")

    dlllist = [str(d) for d in self._config.DLL.split(',')]

    self.table_header(outfd,
                      [("Process", "15"),
                       ("PID", "6"),
                       ("Base", "10"),
                       ("Path", "50")])

    for task in data:
      for m in task.get_load_modules():
        for dll in dlllist:
          # seems to be simple enough fix for r2071 at the moment
          if m.BaseDllName:
            if re.search(dll, str(m.BaseDllName), re.I):
              outfd.write("{0:15} {1:6} {2:10} {3}\n".format(task.ImageFileName, task.UniqueProcessId, m.DllBase, m.FullDllName or ''))
