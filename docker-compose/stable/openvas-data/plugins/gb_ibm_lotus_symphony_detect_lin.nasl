###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Lotus Symphony Version Detection (Linux)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802230");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-12-05T15:10:00+0000");
  script_tag(name:"last_modification", value:"2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)");
  script_tag(name:"creation_date", value:"2011-08-05 09:04:20 +0200 (Fri, 05 Aug 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("IBM Lotus Symphony Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script finds the installed IBM Lotus Symphony version.");
  exit(0);
}


include("ssh_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

use_find = get_kb_item("ssh/lsc/enable_find");
if("no" >< use_find)
{
  close(sock);
  exit(0);
}

if(isnull(use_find)){
  use_find="yes";
}

descend_directories = get_kb_item("ssh/lsc/descend_ofs");
if( isnull( descend_directories ) ) descend_directories = "yes";

## Read "about.mappings" File
cmd = "find / -name about.mappings";

if( "no" >< descend_directories ) cmd += " -xdev";

cmd += " -type f";

paths = split(ssh_cmd(socket:sock, cmd: cmd, timeout:60));
if(paths != NULL)
{
  foreach path (paths)
  {
    if("com.ibm.symphony" >< path) {
      file = ssh_cmd(socket:sock, cmd: "cat " + path);
    }
  }
}

close(sock);
ssh_close_connection();

if(isnull(file) || "Symphony" >!< file){
  exit(0);
}

foreach line(split(file))
{
  version = eregmatch(pattern:"1=([0-9.]+).?([a-zA-Z0-9]+)?", string:line);
  if(version[1] != NULL)
  {
    symVer = version[1];
    if(version[2] != NULL) {
      symVer = version[1] + "." + version[2];
    }
    break;
  }
}

if(symVer)
{
  set_kb_item(name:"IBM/Lotus/Symphony/Lin/Ver", value:symVer);
  log_message(data:"IBM Lotus Symphony version " + symVer +
                     " was detected on the host");
}
