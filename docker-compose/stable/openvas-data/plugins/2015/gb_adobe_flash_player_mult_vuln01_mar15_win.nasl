###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Flash Player Multiple Vulnerabilities - 01 Mar15 (Windows)
#
# Authors:
# Rinu <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805491");
  script_version("2020-10-29T15:35:19+0000");
  script_cve_id("CVE-2015-0342", "CVE-2015-0341", "CVE-2015-0340", "CVE-2015-0339",
                "CVE-2015-0338", "CVE-2015-0337", "CVE-2015-0336", "CVE-2015-0335",
                "CVE-2015-0334", "CVE-2015-0333", "CVE-2015-0332");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)");
  script_tag(name:"creation_date", value:"2015-03-20 15:45:26 +0530 (Fri, 20 Mar 2015)");
  script_name("Adobe Flash Player Multiple Vulnerabilities - 01 Mar15 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash
  Player and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple unspecified use-after-free errors.

  - Multiple unspecified errors due to improper validation of user-supplied input.

  - Multiple unspecified type confusion errors.

  - Integer overflow in adobe Flash Player.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause denial of service execute arbitrary code, bypass intended
  file-upload restrictions or have other unspecified impacts.");

  script_tag(name:"affected", value:"Adobe Flash Player before version
  13.0.0.277 and 14.x through 17.x before 17.0.0.134 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  13.0.0.277 or 17.0.0.134 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-05.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"13.0.0.277"))
{
  fix = "13.0.0.277";
  VULN = TRUE;
}

if(version_in_range(version:playerVer, test_version:"14.0", test_version2:"16.0.0.305"))
{
  fix = "17.0.0.134";
  VULN = TRUE;
}

if(VULN)
{
  report = 'Installed version: ' + playerVer + '\n' +
           'Fixed version:     ' + fix + '\n';
  security_message(data:report);
  exit(0);
}
