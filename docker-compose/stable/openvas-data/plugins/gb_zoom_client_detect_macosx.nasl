###############################################################################
# OpenVAS Vulnerability Test
#
# Zoom Client Version Detection (Mac OS X)
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.814355");
  script_version("2020-04-16T08:24:38+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-04-16 08:24:38 +0000 (Thu, 16 Apr 2020)");
  script_tag(name:"creation_date", value:"2018-12-06 18:04:33 +0530 (Thu, 06 Dec 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Zoom Client Version Detection (Mac OS X)");

  script_tag(name:"summary", value:"Detects the installed version of Zoom Client
  on Mac OS X.

  The script logs in via ssh, searches for folder 'zoom.us.app' and
  queries the related 'info.plist' file for string 'CFBundleShortVersionString'
  via command line option 'defaults read'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

zoomVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /Applications/zoom.us.app/Contents/Info CFBundleShortVersionString"));
close(sock);
if(isnull(zoomVer) || "does not exist" >< zoomVer)
  exit(0);

set_kb_item(name:"zoom/client/detected", value:TRUE);
set_kb_item(name:"zoom/client/mac/detected", value:TRUE);

cpe = build_cpe(value:zoomVer, exp:"^([0-9.]+)", base:"cpe:/a:zoom:zoom:");
if(!cpe)
  cpe = "cpe:/a:zoom:zoom";

# nb: NVD is currently using two different CPEs because Zoom has some inconsistencies in
# their client naming. We register both just to be sure.
cpe2 = build_cpe(value:zoomVer, exp:"^([0-9.]+)", base:"cpe:/a:zoom:meetings:");
if(!cpe2)
  cpe2 = "cpe:/a:zoom:meetings";

register_product(cpe:cpe, location:"/Applications/zoom.us.app", service:"ssh-login", port:0);
register_product(cpe:cpe2, location:"/Applications/zoom.us.app", service:"ssh-login", port:0);

report = build_detection_report(app:"Zoom Client",
                                version:zoomVer,
                                install:"/Applications/zoom.us.app",
                                cpe:cpe,
                                concluded:zoomVer);

log_message(port:0, data:report);

exit(0);
