###############################################################################
# OpenVAS Vulnerability Test
#
# RealPlayer Version Detection (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902106");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2021-06-15T12:39:35+0000");
  script_tag(name:"last_modification", value:"2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"creation_date", value:"2010-02-02 07:26:26 +0100 (Tue, 02 Feb 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("RealPlayer Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of RealPlayer.");
  exit(0);
}

include("ssh_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

rpbin = ssh_find_bin(prog_name:"realplay", sock:sock);
if(isnull(rpbin))
  exit(0);

foreach dir(make_list("/opt/real/RealPlayer", "/usr/local/RealPlayer"))
{
  paths = ssh_find_file(file_name: dir + "/README$", useregex:TRUE, sock:sock);
  foreach binName (paths)
  {

    binName = chomp(binName);
    if(!binName)
      continue;

    rpVer = ssh_get_bin_version(full_prog_name:"cat", version_argv:binName, ver_pattern:"RealPlayer ([0-9.]+)", sock:sock);
    if(rpVer[1] != NULL)
    {
      set_kb_item(name:"RealPlayer/Linux/Ver", value:rpVer[1]);
      log_message(data:"RealPlayer version " + rpVer[1] + " running at location " + binName + " was detected on the host");
      exit(0);
    }
  }
}
ssh_close_connection();
