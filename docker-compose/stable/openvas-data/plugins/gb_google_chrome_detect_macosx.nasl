#############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Version Detection (MacOSX)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802318");
  script_version("2019-12-05T15:10:00+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)");
  script_tag(name:"creation_date", value:"2011-08-10 13:49:51 +0200 (Wed, 10 Aug 2011)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Google Chrome Version Detection (MacOSX)");

  script_tag(name:"summary", value:"Detects the installed version of Google Chrome on Mac OS X.

  The script logs in via ssh, searches for folder 'Google Chrome.app' and
  queries the related 'info.plist' file for string 'CFBundleShortVersionString'
  via command line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

chromeVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/" +
             "Google\ Chrome.app/Contents/Info CFBundleShortVersionString"));

close(sock);

if(isnull(chromeVer) || "does not exist" >< chromeVer){
  exit(0);
}

set_kb_item(name: "GoogleChrome/MacOSX/Version", value:chromeVer);

cpe = build_cpe(value:chromeVer, exp:"^([0-9.]+)", base:"cpe:/a:google:chrome:");
if(isnull(cpe))
  cpe='cpe:/a:google:chrome';

register_product(cpe:cpe, location:'/Applications/Google Chrome.app');

log_message(data: build_detection_report(app: "Google Chrome", version: chromeVer,
                                         install: "/Applications/Google Chrome.app",
                                         cpe: cpe,
                                         concluded: chromeVer));


