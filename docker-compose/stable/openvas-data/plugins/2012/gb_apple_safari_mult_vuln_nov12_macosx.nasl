###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Safari Multiple Vulnerabilities (APPLE-SA-2012-09-19-3)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802484");
  script_version("2020-03-02T13:53:38+0000");
  script_cve_id("CVE-2012-3748", "CVE-2012-5112");
  script_bugtraq_id(56362, 55867);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-03-02 13:53:38 +0000 (Mon, 02 Mar 2020)");
  script_tag(name:"creation_date", value:"2012-11-02 15:21:30 +0530 (Fri, 02 Nov 2012)");
  script_name("Apple Safari Multiple Vulnerabilities (APPLE-SA-2012-09-19-3)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT1222");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5568");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51157/");
  script_xref(name:"URL", value:"http://prod.lists.apple.com/archives/security-announce/2012/Nov/msg00001.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to bypass certain security
  restrictions and compromise a user's system.");

  script_tag(name:"affected", value:"Apple Safari versions prior to 6.0.2 Mac OS X.");

  script_tag(name:"insight", value:"- A race condition error exists within the webkit component when handling
  JavaScript arrays and can be exploited to execute arbitrary code.

  - A use-after-free error exists in the handling of SVG images.");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 6.0.2 or later.");

  script_tag(name:"summary", value:"This host is installed with Apple Safari web browser and is prone
  to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName || "Mac OS X" >!< osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if(version_is_equal(version:osVer, test_version:"10.7.5") ||
   version_is_equal(version:osVer, test_version:"10.8.2")) {

  if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
    exit(0);

  vers = infos["version"];
  path = infos["location"];

  if(version_is_less(version:vers, test_version:"6.0.2")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"6.0.2", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
