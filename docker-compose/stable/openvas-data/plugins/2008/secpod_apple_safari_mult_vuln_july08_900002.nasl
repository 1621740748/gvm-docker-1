##############################################################################
# OpenVAS Vulnerability Test
# Description: Apple Safari for Windows Multiple Vulnerabilities July-08
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900002");
  script_version("2020-02-28T13:41:47+0000");
  script_tag(name:"last_modification", value:"2020-02-28 13:41:47 +0000 (Fri, 28 Feb 2020)");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_bugtraq_id(29412, 29413, 29835, 29835);
  script_cve_id("CVE-2008-1573", "CVE-2008-2306", "CVE-2008-2307");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("General");
  script_name("Apple Safari for Windows Multiple Vulnerabilities July-08");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");

  script_tag(name:"solution", value:"Update Safari to version 3.1.2.");

  script_tag(name:"summary", value:"The host is installed with Apple Safari Web Browser, which is
  prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The vulnerability exists due to,

  - improper handling of BMP and GIF images that can lead to disclosure of
  system memory contents.

  - handling of files that are downloaded from a website which is in
  Internet Explorer 7 Zone with the Launching applications and unsafe files set to
  Enable, or in the Internet Explorer 6 Local Intranet or Trusted sites zone causing
  safari to launch unsafe executables.

  - an error in handling JavaScript arrays that can lead to memory corruption.");

  script_tag(name:"affected", value:"Apple Safari versions prior to 3.1.2 on Windows (All).");

  script_tag(name:"impact", value:"Successful exploitation by attacker could lead to exposure of
  sensitive information, system access or denying the application and allow execution of arbitrary code.");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT2092");
  script_xref(name:"URL", value:"http://secunia.com/advisories/30801/");
  script_xref(name:"URL", value:"http://secunia.com/advisories/30775/");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/1882");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Jun/1020330.html");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(egrep(pattern:"^(2\..*|3\.(52[2-4]\..*|525\.([01][0-9]|20)\..*))$", string:vers)) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Safari 3.1.2 (output of installed version differ from actual Safari version)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
