###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Acrobat and Reader PDF Handling Code Execution Vulnerability (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804267");
  script_version("2020-05-28T14:41:23+0000");
  script_cve_id("CVE-2010-0188", "CVE-2010-0186");
  script_bugtraq_id(38195, 38198);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-05-28 14:41:23 +0000 (Thu, 28 May 2020)");
  script_tag(name:"creation_date", value:"2014-04-16 15:25:45 +0530 (Wed, 16 Apr 2014)");
  script_name("Adobe Acrobat and Reader PDF Handling Code Execution Vulnerability (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Adobe Reader/Acrobat and is prone to remote code
  execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is caused by a memory corruption error in the 'authplay.dll' module
  when processing malformed Flash data within a PDF document and some unspecified error.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code by tricking
  a user into opening a PDF file embedding a malicious Flash animation and bypass
  intended sandbox restrictions allowing cross-domain requests.");

  script_tag(name:"affected", value:"Adobe Reader version 8.x before 8.2.1 and 9.x before 9.3.1 on Mac OS X.

  Adobe Acrobat version 8.x before 8.2.1 and 9.x before 9.3.1 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader/Acrobat version 9.3.1 or 8.2.1 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56297");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0399");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Feb/1023601.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-07.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader/MacOSX/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:adobe:acrobat_reader",
                     "cpe:/a:adobe:acrobat");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"8.2.1") ||
   version_in_range(version:vers, test_version:"9.0", test_version2:"9.3.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"9.3.1 or 8.2.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
