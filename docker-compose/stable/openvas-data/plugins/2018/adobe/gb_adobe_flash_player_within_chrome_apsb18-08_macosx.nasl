##############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Flash Player Within Google Chrome Security Update(apsb18-08)- MAC OS X
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:flash_player_chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813209");
  script_version("2021-06-01T06:00:14+0200");
  script_cve_id("CVE-2018-4932", "CVE-2018-4933", "CVE-2018-4934", "CVE-2018-4935",
                "CVE-2018-4936", "CVE-2018-4937");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-06-01 06:00:14 +0200 (Tue, 01 Jun 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-07 20:14:00 +0000 (Thu, 07 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-04-11 10:51:53 +0530 (Wed, 11 Apr 2018)");
  script_name("Adobe Flash Player Within Google Chrome Security Update(apsb18-08)- MAC OS X");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"- A remote code-execution vulnerability that occurs due to a use-after-free
    condition.

  - Multiple remote code-execution vulnerabilities that occur due to an
    out-of-bounds write error.

  - Multiple information-disclosure vulnerabilities that occur due to an
    out-of-bounds read error.

  - An information-disclosure vulnerability that occurs due to a heap overflow
    condition .");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to gain th control of the affected system. Depending on the
  privileges associated with this application, an attacker could then install
  programs, view, change, or delete data, or create new accounts with full
  user rights.");

  script_tag(name:"affected", value:"Adobe Flash Player prior to 29.0.0.140
  within Google Chrome on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player for
  Google Chrome 29.0.0.140, or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb18-08.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_flash_player_within_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Chrome/MacOSX/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"29.0.0.140"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"29.0.0.140", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
