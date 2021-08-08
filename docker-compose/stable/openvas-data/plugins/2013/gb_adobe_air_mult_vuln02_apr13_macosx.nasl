###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe AIR Multiple Vulnerabilities -02 April 13 (Mac OS X)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803386");
  script_version("2020-10-20T15:03:35+0000");
  script_cve_id("CVE-2013-1380", "CVE-2013-1379", "CVE-2013-1378", "CVE-2013-2555");
  script_bugtraq_id(58949, 58951, 58947, 58396);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2013-04-19 11:30:01 +0530 (Fri, 19 Apr 2013)");
  script_name("Adobe AIR Multiple Vulnerabilities -02 April 13 (Mac OS X)");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/52931");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-11.html");
  script_xref(name:"URL", value:"http://www.cert.be/pro/advisories/adobe-flash-player-air-multiple-vulnerabilities-3");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Air/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code or cause  denial-of-service condition.");
  script_tag(name:"affected", value:"Adobe AIR Version 3.6.0.6090 and prior on Windows");
  script_tag(name:"insight", value:"Multiple flaws due to,

  - Error when initializing certain pointer arrays.

  - Integer overflow error.");
  script_tag(name:"solution", value:"Upgrade to version 3.7.0.1530 or later.");
  script_tag(name:"summary", value:"This host is installed with Adobe AIR and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Adobe/Air/MacOSX/Version");
if(vers) {
  if(version_is_less_equal(version:vers, test_version:"3.6.0.6090"))
  {
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"Less than or equal to 3.6.0.6090");
    security_message(port: 0, data: report);
    exit(0);
  }
}
