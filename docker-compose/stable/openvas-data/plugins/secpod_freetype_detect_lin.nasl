###############################################################################
# OpenVAS Vulnerability Test
#
# FreeType Version Detection (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900626");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2021-06-15T12:39:35+0000");
  script_tag(name:"last_modification", value:"2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"creation_date", value:"2009-04-24 16:23:28 +0200 (Fri, 24 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("FreeType Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"Detects the installed version of FreeType.

  The script logs in via SSH, searches for executable 'freetype-config' and
  queries the found executables via command line option '--ftversion'.");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

binFiles = ssh_find_file(file_name:"/freetype-config$", useregex:TRUE, sock:sock);

foreach executableFile (binFiles) {

  executableFile = chomp(executableFile);
  if(!executableFile)
    continue;

  ftVer = ssh_get_bin_version(full_prog_name:executableFile, sock:sock, version_argv:"--ftversion", ver_pattern:"[0-9.]{3,}");
  if(ftVer[0] != NULL)
  {
    set_kb_item(name:"FreeType/Linux/Ver", value:ftVer[0]);
    register_and_report_cpe( app:"FreeType",
                             ver:ftVer[1],
                             concluded: ftVer[0],
                             base:"cpe:/a:freetype:freetype:",
                             expr:"^([0-9.]+)",
                             insloc:executableFile,
                             regService:"ssh-login" );
  }
}

ssh_close_connection();
