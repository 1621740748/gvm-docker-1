###############################################################################
# OpenVAS Vulnerability Test
#
# G15Daemon Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900853");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-03-27T14:05:33+0000");
  script_tag(name:"last_modification", value:"2020-03-27 14:05:33 +0000 (Fri, 27 Mar 2020)");
  script_tag(name:"creation_date", value:"2009-09-18 08:01:03 +0200 (Fri, 18 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("G15Daemon Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of G15Daemon.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "G15Daemon Version Detection";

g15d_sock = ssh_login_or_reuse_connection();
if(!g15d_sock)
  exit(0);

g15dName = ssh_find_bin(prog_name:"g15daemon", sock:g15d_sock);
foreach binName (g15dName)
{

  binName = chomp(binName);
  if(!binName)
    continue;

  g15dVer = ssh_get_bin_version(full_prog_name:binName, sock:g15d_sock, version_argv:"-version", ver_pattern:"G15Daemon version ([0-9]\.[0-9.]+([a-z]+)?)");
  if(g15dVer[1] != NULL){
    set_kb_item(name:"G15Daemon/Ver", value:g15dVer[1]);
    log_message(data:"G15Daemon version " + g15dVer[1] + " running at location " + binName + " was detected on the host");

    cpe = build_cpe(value:g15dVer[1], exp:"^([0-9.]+)", base:"cpe:/a:g15tools:g15daemon:");
    if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);
  }
}
ssh_close_connection();
