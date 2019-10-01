# filepath was created by Glenn P. Edwards Jr.
#      https://hiddenillusion.github.io
#            @hiddenillusion
# (while at FireEye)
# Version 0.1.6
# Date: 2013-12-10
# Requirements:
#        - written and tested with Volatility v2.4
# To-Do:
#       [x] fix https://code.google.com/p/volatility/source/detail?r=2071
#   [x] need to work out matching filename's basename at root of path_exact_list locations
# [ ] directly inherit handles plugin instead of copying/modifying it below?
# [ ] need to incorporate SysWoW64 for baseline dll path check
#   [x] doing check if right @ root yields a lot or dirs... maybe check for extenstion?
#   [x] svcscan & check binary path?
# [ ] need to account for "'s in the file paths (e.g. svc's)
#   - "C:\Program Files (x86)\Intel\Intel(R) Management Engine Components\UNS\UNS.exe" in  XtremeRAT_Win7SP0x64.im
#   [ ] add paths from process's PEB (in pstree with -v prior to Volatility 2.0)
# [ ] symlink scan useful?
# [ ] driver scan useful?
# [ ] psxview -> full path to PE, any different than dlllist?
# [x] sre_constants.error for names like 'HarddiskVolume2????????' fixed with re.compile(path + re.escape(fname), re.I)

import re
import os
import volatility.win32.modules as modules #remove?
import volatility.plugins.pstree as pstree
import volatility.plugins.taskmods as taskmods
import volatility.plugins.filescan as filescan
import volatility.plugins.iehistory as iehistory
import volatility.plugins.malware.svcscan as svcscan
import volatility.plugins.malware.psxview as psxview
import volatility.plugins.registry.shellbags as shellbags
import volatility.plugins.registry.shimcache as shimcache
import volatility.plugins.registry.registryapi as registryapi #remove?

'''
# Have seen the following as root paths:
#- \\Device\\HarddiskVolume\d\\ -> handles
#- \\??\\C:\\ -> only csrss.exe & winlogon.exe on Win7
#- C:\\
#- c:\\
#- \\SystemRoot\\ -> only smss.exe though
#- %systemroot%\\ -> ServiceDLL's within svcscan
'''

class FilePath(taskmods.DllList, svcscan.SvcScan):
  """Search for files in questionable locations"""

  def __init__(self, config, *args, **kwargs):
    taskmods.DllList.__init__(self, config, *args, **kwargs)
    config.add_option("whitelist", default = False,
            action = 'store_true',
            help = 'Filter out some common locations that add noise')

  def compile_regex(self, paths):
    """
    Pre-compile the regular expression rules. It's quicker
    if we do this once per plugin run vs. once per
    path that needs checking.
    """
    if isinstance(paths, list):
      ret = []
      for regex in paths:
        ret.append(re.compile(regex, re.I))
      return ret
    else:
      return re.compile(paths, re.I)

  def _has_extension(self, path):
    """
    Cheater function to do a simple check and
    see if a path ends in something that looks like
    an extension so we can (blindly) try and exclude
    directories. This helps a lot with file handles.
    """
    if re.match(r'.*\\.*\..*$', path):
      return True

  def _is_whitelisted(self, path, name, method):
    """ Whitelist of some paths to filter out some generally common noise """
    # This would be more flexible as an imported file but I gues having some static paths can be beneficial too..
    # You're going to potentially miss out on good stuff, e.g. - if a program has a handle to one of these that shouldn't
    ok_handle = [r'.*\\Application Data\\AVG.*',
                 r'.*\\BigFix Enterprise\\BES Client.*',
                 r'.*\\cygwin\\.*',
                 r'.*\\Local Settings\\History\\History\.IE5\\index\.dat*',                                    # iexplore, explorer
                 r'.*\\Local Settings\\Temporary Internet Files\\Content\.IE5\\index\.dat',                    # iexplore, explorer
                 r'.*\\I386\\.*',
                 r'.*\\Java\\jre.*',
                 r'.*\\Perl\\.*',
                 r'.*\\Microsoft\\CryptnetUrlCache\\.*',
                 r'.*\\Microsoft\\Windows\\UsrClass\.dat.*',
                 r'.*\\Microsoft Silverlight\\.*',
                 r'.*\\Program Files\\Microsoft SQL Server\\.*',
                 r'.*\\Ruby\\.*',
                 r'.*\\System Volume Information\\_restore.*',
                 r'.*\\Temp\\ASPNETSetup_.*',
                 r'.*\\Temp\\Microsoft .NET Framework.*',
                 r'.*\\Users\\.*\\AppData\\Local\\Microsoft\\Outlook\\.*\.ost',                                   # outlook
                 r'.*\\Users\\.*\\AppData\\Local\\Microsoft\\Outlook\\Offline Address Books\\.*\.oab',            # outlook
                 r'.*\\Users\\.*\\AppData\\Local\\Microsoft\\Windows\\Explorer\\thumbcache_.*\.db',               # iexplore
                 r'.*\\Users\\.*\\AppData\\Local\\Microsoft\\Windows\\History\\History.IE5\\.*\\index\.dat',      # iexplore, explorer
                 r'.*\\Users\\.*\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content\.IE5\\.*',# iexplore, explorer
                 r'.*\\Windows\\CCM\\.*',
                 r'.*\\Windows\\Fonts\\.*',
                 r'.*\\Windows\\Help\\.*',
                 r'.*\\Windows\\inf\\.*',
                 r'.*\\Windows\\Installer\\.*',
                 r'.*\\WINDOWS\\Microsoft.NET\\.*',
                 r'.*\\Windows\\PCHealth\\.*',
                 #r'.*\\WINDOWS\\$hf_mig$\\.*',
                 #r'.*\\WINDOWS\\$NtUninstallKB.*',
                 r'.*\\WINDOWS\\assembly\\.*',
                 r'.*\\Windows\\GatherLogs\\SystemIndex\\SystemIndex.*',
                 r'.*\\WINDOWS\\ie7updates\\.*',
                 r'.*\\WINDOWS\\ie8updates\\.*',
                 r'.*\\Windows\\servicing\Packages\\.*',
                 r'.*\\Windows\\ServiceProfiles\\.*',
                 r'.*\\Windows\\ServicePackFiles\\.*',
                 r'.*\\WINDOWS\\SoftwareDistribution\\.*',
                 r'.*\\Windows\\System32\\CatRoot\\.*',
                 r'.*\\WINDOWS\\system32\\config\\.*',
                 r'.*\\WINDOWS\\system32\dllcache\\.*',
                 r'.*\\Windows\\System32\\DriverStore\\FileRepository\\.*',
                 r'.*\\WINDOWS\\System32\\en-us\\.*',
                 r'.*\\Windows\\System32\\EventProviders\\.*',
                 r'.*\\WINDOWS\\System32\\mui\\.*',
                 r'.*\\Windows\\System32\\spool\\drivers.*',                                                      # winlogon
                 r'.*\\WINDOWS\\System32\\Microsoft\\Protect\\.*',
                 r'.*\\Windows\\System32\\MsDtc\\.*',
                 r'.*\\Windows\\System32\\wbem\\.*',                                                              # winlogon
                 r'.*\\Windows\\System32\\winevt\\Logs\\.*\.evtx',                                                # svchost, winlogon
                 r'.*\\Windows\\WinSxS\\.*',
                ]
    """
    baseline_path_lst = {'smss.exe' : r'\\SystemRoot\\System32\\smss.exe',
                         'csrss.exe' : r'.*:\\windows\\system32\\csrss.exe',
                         'winlogon.exe' : r'.*:\\windows\\system32\\winlogon.exe',
                         'services.exe' : r'.*\\windows\\system32\\services.exe',
                         'svchost.exe' : r'.*\\windows\\system32\\svchost.exe',
                         'explorer.exe' : r'.*\\windows\\explorer.exe',
                         'ctfmon.exe' : r'.*\\windows\\system32\\ctfmon.exe'
                        }
    """

    ok_file = [r'.*\\Device\\Afd\\Endpoint',
               r'.*\\Device\\HarddiskVolume\d\\\$.*',
               r'.*\\Device\\HarddiskVolume\d\\.*\\(Application Data|Local Settings|My Documents|Quick Launch)\\desktop\.ini',
               r'.*\\Device\\HarddiskVolume\d\\.*\\Application Data\\Microsoft\\.*security\.config\.cch',
               r'.*\\Device\\HarddiskVolume\d\\Program Files\\Broadcom\\.*',
               r'.*\\Device\\(HarddiskVolume\d\\)?Program Files\\AVG\\.*',
               r'.*\\Device\\HarddiskVolume\d\\Program Files \(x86\)\\AVG\\.*',
               r'.*\\Device\\HarddiskVolume\d\\Program Files \(x86\)\\Dell\\.*',
               r'.*\\Device\\HarddiskVolume\d\\Program Files \(x86\)\\Internet Explorer\\iexplore\.exe',
               r'.*\\Device\\HarddiskVolume\d\\Program Files \(x86\)\\NSClient.*',
               r'.*\\Device\\HarddiskVolume\d\\Windows\\System32\\catroot\\.*',
               r'.*\\Device\\HarddiskVolume\d\\Windows\\System32\\en-US\\.*',
               #r'.*\\Device\\HarddiskVolume\d\\WINDOWS\\system32\\inetsrv\\.*',
               r'.*\\Device\\HarddiskVolume\d\\WINDOWS\\system32\\LogFiles\\.*',
              ]

    ok_internet = [r'Cookie:.*@.*addthis.com',
                   r'Cookie:.*@.*bing.com',
                   r'Cookie:.*@.*doubleclick.net',
                   r'Cookie:.*@.*google.com',
                   r'Cookie:.*@.*msn.com',
                   r'Cookie:.*@.*quantserver.com',
                   r'Cookie:.*@.*twitter.com',
                   r'Cookie:.*@.*youtube.com',
                  ]

    ok_svc = {'AudioSrv': r'.*\\WINDOWS\\System32\\svchost\.exe -k netsvcs',
              'Browser': r'.*\\WINDOWS\\System32\\svchost\.exe -k netsvcs',
              'CryptSvc': r'.*\\WINDOWS\\System32\\svchost\.exe -k netsvcs',
              'DcomLaunch': r'.*\\WINDOWS\\system32\\svchost\.exe -k DcomLaunch',
              'Dhcp': r'.*\\WINDOWS\\system32\\svchost\.exe -k NetworkService',
              'Dnscache': r'.*\\WINDOWS\\system32\\svchost\.exe -k NetworkService',
              'ERSvc': r'.*\\WINDOWS\\System32\\svchost\.exe -k WinErr',
              'Eventlog': r'.*\\WINDOWS\\system32\\services\.exe',
              'EventSystem': r'.*\\WINDOWS\\System32\\svchost\.exe -k netsvcs',
              'helpsvc': r'.*\\WINDOWS\\System32\\svchost.exe -k netsvcs',
              'HidServ': r'.*\\WINDOWS\\System32\\svchost\.exe -k netsvcs',
              'HTTPFilter': r'.*\\WINDOWS\\system32\\lsass\.exe',
              'lanmanserver': r'.*\\WINDOWS\\System32\\svchost\.exe -k netsvcs',
              'lanmanworkstation': r'.*\\WINDOWS\\System32\\svchost\.exe -k netsvcs',
              'LmHosts': r'.*\\WINDOWS\\System32\\svchost\.exe -k LocalService',
              'MSDTC': r'.*\\WINDOWS\\System32\\msdtc\.exe',
              'PlugPlay': r'.*\\WINDOWS\\system32\\services\.exe',
              'PolicyAgent': r'.*\\WINDOWS\\system32\\lsass.exe',
              'ProtectedStorage': r'.*\\WINDOWS\\system32\\lsass.exe',
              'RasMan': r'.*\\WINDOWS\\System32\\svchost\.exe -k netsvcs',
              'RemoteRegistry': r'.*\\WINDOWS\\system32\\svchost\.exe -k regsvc',
              'RpcSs': r'.*\\WINDOWS\\system32\\svchost\.exe -k rpcss',
              'SamSs': r'.*\\WINDOWS\\system32\\lsass\.exe',
              'Schedule': r'.*\\WINDOWS\\System32\\svchost\.exe -k netsvcs',
              'seclogon': r'.*\\WINDOWS\\System32\\svchost\.exe -k netsvcs',
              'ShellHWDetection': r'.*\\WINDOWS\\System32\\svchost\.exe -k netsvcs',
              'SNMP': r'.*\\WINDOWS\\System32\\snmp\.exe',
              'Spooler': r'.*\\WINDOWS\\system32\\spoolsv\.exe',
              'SrmSvc': r'.*\\WINDOWS\\system32\\svchost\.exe -k srmsvcs',
              'TapiSrv': r'.*\\WINDOWS\\System32\\svchost\.exe -k tapisrv',
              'TermService': r'.*\\WINDOWS\\System32\\svchost\.exe -k termsvcs',
              'W32Time': r'.*\\WINDOWS\\system32\\svchost\.exe -k LocalService',
              'wuauserv': r'.*\\WINDOWS\\System32\\svchost\.exe -k netsvcs',
              'WZCSVC': r'.*\\WINDOWS\\System32\\svchost\.exe -k netsvcs',
             }

    if method == "File":
      combined_file = ok_file + ok_handle
      for ok_path in self.compile_regex(combined_file):
        if re.search(ok_path, path):
          return True

    if method == "Handle":
      for ok_path in self.compile_regex(ok_handle):
        if re.search(ok_path, path):
          return True

    if method == "Internet":
      for ok_path in self.compile_regex(ok_internet):
        cleaner_path = path.replace(" ", "")
        if re.search(ok_path, cleaner_path):
          return True

    if method == "Service":
      for svc_name, svc_path in ok_svc.iteritems():
        if name.lower() == svc_name.lower():
          sp = self.compile_regex(svc_path)
          if re.match(sp, path):
            return True

  def _is_blacklisted(self, path, name, method):
    """ Flexible location search """
    bad_handle = [r'.*\\Temp\\.*',
                  r'.*\\Recycler\\.*',
                  r'.*\\$Recycle\.Bin\\.*',
                  r'.*\\Users\\.*\\AppData\\.*',
                  r'.*\\Users\\.*\\Desktop\\.*',
                  r'.*\\Users\\.*\\Downloads\\.*',
                  r'.*\\Users\\.*\\My Documents\\.*',
                  r'.*\\ProgramData\\.*',
                  r'.*\\Program Files\\.*',         #remove, svc test
                  r'.*\\Program Files \(x86\)\\.*', #remove, svc test
                  r'.*\\Documents and Settings\\.*\\Application Data\\.*',
                  r'.*\\Documents and Settings\\.*\\My Documents\\.*',
                  r'.*\\Documents and Settings\\.*\\Local Settings\\.*', # will catch stuff on Desktop too
                  r'.*\\Windows\\system32\\.*\\.*', # will find lower level stuff but not a new folder they created right under sys32...
                 ]

    bad_internet = [r'.*@file://.*',
                   ]

    bad_svc = [r'.*\\Windows\\System32\\.*',
               r'.*\\Driver\\.*',
               r'.*\\FileSystem\\.*',
              ]

    if method == "Handle" or method == "File":
      for bad_path in self.compile_regex(bad_handle):
        if re.search(bad_path, path):
          return True

    if method == "Service":
      cnt = 0
      for bad_path in self.compile_regex(bad_svc):
        # easier than negating regexes above in case you want to add a true bad path
        if re.search(bad_path, path):
          cnt += 1
          if self._has_extension(path):
            return True
      # if we arrive here without matching any of the bad_svc paths then we want to know what it is
      if cnt < 1:
        return True

  def calculate(self):
    """ Look at Process paths """
    #process_data = psxview.PsXview(self._config).calculate()
    #for offset, eprocess, ps_sources in process_data:
    #   method = "Process"
    #    pid = eprocess.UniqueProcessId
    #    name = (eprocess.ImageFileName or '')
    #    path = ' # check volshell > dt("_EPROCESS") for attrib?
    #    yield method, pid, name, '-'

    """ Look at Internet paths """
    internet_data = iehistory.IEHistory(self._config).calculate()
    for process, record in internet_data:
      method = "Internet"
      proc = process.ImageFileName
      pid = process.UniqueProcessId
      fpath = record.Url
      if record.FileOffset > 0:
        fpath = fpath +' | '+record.File
      if self._config.whitelist:
        if self._is_whitelisted(fpath, proc, method):
          continue
      yield method, pid, proc, fpath

    for task in taskmods.DllList.calculate(self):
      pid = task.UniqueProcessId
      proc = str(task.ImageFileName)

      """ Look at the Handle file paths """
      if task.ObjectTable.HandleTableList:
        for handle in task.ObjectTable.handles():

          if not handle.is_valid():
            continue

          method = "Handle"
          object_type = handle.get_object_type()
          if object_type == "File":
            # Only look at "File" object_type's
            file_obj = handle.dereference_as("_FILE_OBJECT")
            fpath = str(file_obj.file_name_with_device())
            #fname = str(fpath).rsplit('\\',1)[1] # might get IndexError
            if fpath:
              if self._config.whitelist:
                if self._is_whitelisted(fpath, None, method):
                  continue
              if not self._has_extension(fpath):
                continue
              if self._is_blacklisted(fpath, None, method):
                yield method, pid, proc, fpath

      """ Look at file paths in processes CLI args """
      cmdline = ""
      if task.Peb:
       method = "CLI"
       fpath = "{0}".format(str(task.Peb.ProcessParameters.CommandLine or '')).strip()
       if self._config.whitelist:
        if self._is_whitelisted(fpath, proc, method):
          continue
       if not self._has_extension(fpath):
          continue
       if self._is_blacklisted(fpath, proc, method):
          yield method, pid, proc, fpath

    """ Look at Service file paths """
    scanner = svcscan.SvcScan(self._config)
    for service in scanner.calculate():
      method = "Service"
      name = str(service.ServiceName.dereference() or '')
      if service.Binary:
        fpath = service.Binary.strip('"')
        if self._config.whitelist:
          if self._is_whitelisted(fpath, name, method):
            continue
        if self._is_blacklisted(fpath, name, method):
          yield method, "-", name, fpath

    """ Look at file paths """
    scanner = filescan.FileScan(self._config)
    for fobj in scanner.calculate():
      method = "File"
      fpath = str(fobj.file_name_with_device() or '')
      if fpath:
        if self._config.whitelist:
          if self._is_whitelisted(fpath, None, method):
            continue
        if not self._has_extension(fpath):
          continue
        if self._is_blacklisted(fpath, None ,method):
          yield method, '-', '-', fpath

    """ Look at ShimCache file paths """
    shimcache_data = shimcache.ShimCache(self._config).calculate()
    if shimcache_data:
      method = "Shim"
      for path, last_modified, last_updated in shimcache_data:
        fpath = str(path).strip()
        yield method, '-', '-', fpath

    # takes a long time...
    """ Look at Shellbag file paths """
    #shellbag_data = shellbags.ShellBags(self._config).calculate()
    #if shellbag_data:
    #    method = "Shellbag"
    #    try:
    #        for item, shell, path in shellbag_data:
    #            yield method, '-', '-', path
    #    except Exception as err:
    #        print err
    #        for item, num, shell, path in shellbag_data:
    #            yield method, '-', '-', path

    """ Look at SymLink file paths """
    #scanner = filescan.SymLinkScan(self._config)
    #for symlink in scanner.calculate():
    #    method = "SymLink"
    #    fpath = str(symlink.LinkTarget or '')
    #    yield method, '-', '-', fpath

    """ Look at Driver file paths """
    #scanner = filescan.DriverScan(self._config)
    #for driver in scanner.calculate():
    #    method = "Driver"
    #    fpath = str(driver.DriverName or '')
    #    yield method, '-', '-', fpath

  def render_text(self, outfd, data):
    self.table_header(outfd,
                      [("Type", "8"),
                       ("PID", "6"),
                       ("Name", "25"),
                       ("Path", "55")])
    for method, pid, name, path in data:
      outfd.write("{0:8} {1:6} {2:25} {3}\n".format(method, pid, name, path))
