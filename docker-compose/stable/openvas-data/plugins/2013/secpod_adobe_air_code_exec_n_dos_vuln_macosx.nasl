# Copyright (C) 2013 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903318");
  script_version("2021-08-05T12:20:54+0000");
  script_cve_id("CVE-2012-0772", "CVE-2012-0773", "CVE-2012-0724", "CVE-2012-0725");
  script_bugtraq_id(52748, 52916, 52914);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-08-06 10:23:56 +0000 (Fri, 06 Aug 2021)");
  script_tag(name:"creation_date", value:"2013-08-26 14:01:59 +0530 (Mon, 26 Aug 2013)");
  script_name("Adobe Air Code Execution and DoS Vulnerabilities (MAC OS X)");
  script_tag(name:"summary", value:"This host is installed with Air and is prone to code execution and denial of
service vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to Adobe Air version 3.2.0.2070 or later.");
  script_tag(name:"insight", value:"The flaws are due to

  - An error within an ActiveX Control when checking the URL security domain.

  - An unspecified error within the NetStream class.");
  script_tag(name:"affected", value:"Adobe AIR version prior to 3.2.0.2070 on MAC OS X");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via unknown vectors.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48623");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1026859");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-07.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Air/MacOSX/Version");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Adobe/Air/MacOSX/Version");
if(vers) {
  if(version_is_less(version:vers, test_version:"3.2.0.2070"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"3.2.0.2070");
    security_message(port: 0, data: report);
    exit(0);
  }
}
