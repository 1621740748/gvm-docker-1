###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Reader 'File Extension' Buffer Overflow Vulnerability (Windows)
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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804260");
  script_version("2020-10-20T15:03:35+0000");
  script_cve_id("CVE-2004-0632");
  script_bugtraq_id(10696);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2014-04-16 10:27:12 +0530 (Wed, 16 Apr 2014)");
  script_name("Adobe Reader 'File Extension' Buffer Overflow Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Reader and is prone to buffer overflow
vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw exist due to a parsing and boundary error when splitting filename paths
into components.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to conduct denial of service and
possibly execute arbitrary code.");
  script_tag(name:"affected", value:"Adobe Reader version 6.0 and 6.0.1 on Windows.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader 6.0.2 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/12053");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/16667");
  script_xref(name:"URL", value:"http://www.adobe.com/support/techdocs/330527.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.1")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"6.0 - 6.0.1");
  security_message(port:0, data:report);
  exit(0);
}
