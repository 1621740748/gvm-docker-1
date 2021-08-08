###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Flash Player/AIR Detection (Linux/Unix SSH Login)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800032");
  script_version("2021-06-15T12:39:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"creation_date", value:"2008-10-21 16:25:40 +0200 (Tue, 21 Oct 2008)");
  script_name("Adobe Flash Player/AIR Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Adobe Flash Player/AIR.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

air_sock = ssh_login_or_reuse_connection();
if(!air_sock)
  exit(0);

garg[0] = "-o";
garg[1] = "-m1";
garg[2] = "-a";
garg[3] = string("[0-9]\\+,[0-9]\\+,[0-9]\\+,[0-9]\\+");

flashName = ssh_find_file(file_name:"/libflashplayer\.so$", useregex:TRUE, sock:air_sock);
if(flashName) {

  foreach binaryName(flashName) {

    binaryName = chomp(binaryName);
    if(!binaryName)
      continue;

    #nb: Adobe AIR also has libflashplayer.so file so confirming that it is not Adobe AIR
    if("AIR" >< binaryName)
      continue;

    binaryName = ereg_replace(pattern:" ", replace:"\ ", string:binaryName);

    arg = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string(0x22) + garg[3] + raw_string(0x22) + " " + binaryName;

    flashVer = ssh_get_bin_version(full_prog_name:"grep", version_argv:arg, sock:air_sock, ver_pattern:"([0-9]+,[0-9]+,[0-9]+,[0-9]+)");
    if(flashVer[1]) {

      flashVer = ereg_replace(pattern:",|_|-", string:flashVer[1], replace:".");

      set_kb_item(name:"Adobe/Air_or_Flash_or_Reader_or_Acrobat/Linux/Installed", value:TRUE);
      set_kb_item(name:"AdobeFlashPlayer/Linux/Ver", value:flashVer);
      set_kb_item(name:"adobe/flash_player/detected", value:TRUE);

      register_and_report_cpe(app:"Adobe Flash Player", ver:flashVer, base:"cpe:/a:adobe:flash_player:", expr:"^([0-9.]+)", regPort:0, insloc:binaryName, concluded:flashVer, regService:"ssh-login");
    }
  }
}

airPaths = ssh_find_file(file_name:"/ApolloVersion$", useregex:TRUE, sock:air_sock);
if(!airPaths) {
  ssh_close_connection();
  exit(0);
}

foreach binaryName(airPaths) {

  binaryName = chomp(binaryName);
  if(!binaryName || "Adobe" >!< binaryName)
    continue;

  airPath = ereg_replace(pattern:" ", replace:"\ ", string:binaryName);

  airVer = ssh_get_bin_version(full_prog_name:"cat", version_argv:airPath, ver_pattern:"([0-9.]+)", sock:air_sock);
  if(airVer[1]) {

    airVer = ereg_replace(pattern:",|_|-", string:airVer[1], replace:".");

    set_kb_item(name:"Adobe/Air_or_Flash_or_Reader/Linux/Installed", value:TRUE);
    set_kb_item(name:"Adobe/Air/Linux/Ver", value:airVer);

    register_and_report_cpe(app:"Adobe AIR", ver:airVer, base:"cpe:/a:adobe:adobe_air:", expr:"^([0-9.]+)", regPort:0, insloc:binaryName, concluded:airVer, regService:"ssh-login");
  }
}

ssh_close_connection();
exit(0);
