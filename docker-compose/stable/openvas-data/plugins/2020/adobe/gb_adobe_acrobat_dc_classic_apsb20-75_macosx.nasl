# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:adobe:acrobat_dc_classic";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817859");
  script_version("2021-07-08T02:00:55+0000");
  script_cve_id("CVE-2020-29075");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-07-08 02:00:55 +0000 (Thu, 08 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-26 16:43:00 +0000 (Fri, 26 Feb 2021)");
  script_tag(name:"creation_date", value:"2020-12-10 11:51:30 +0530 (Thu, 10 Dec 2020)");
  script_name("Adobe Acrobat Classic 2020 Security Update(apsb20-75) - Mac OS X");

  script_tag(name:"summary", value:"This host is installed with Adobe Acrobat
  Classic 2020 and is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper input validation
  error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to disclose sensitive information.");

  script_tag(name:"affected", value:"Adobe Acrobat Classic 2020 prior to version
  2020.001.30018on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat Classic 2020 version
  2020.001.30018 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb20-75.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_dc_classic_detect_macosx.nasl");
  script_mandatory_keys("Adobe/AcrobatDC/Classic/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
readerVer = infos['version'];
InstallPath = infos['location'];

if(version_in_range(version:readerVer, test_version:"20.0", test_version2:"20.001.30017"))
{
  report = report_fixed_ver(installed_version:readerVer, fixed_version:"20.001.30018(2020.001.30018)", install_path:InstallPath);
  security_message(data:report);
  exit(0);
}
exit(99);
