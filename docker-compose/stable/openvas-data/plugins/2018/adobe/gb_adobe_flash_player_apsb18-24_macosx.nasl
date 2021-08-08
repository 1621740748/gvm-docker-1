##############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Flash Player Security Updates(apsb18-24)-MAC OS X
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813639");
  script_version("2021-06-01T06:00:15+0200");
  script_cve_id("CVE-2018-5008", "CVE-2018-5007");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-06-01 06:00:15 +0200 (Tue, 01 Jun 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-17 17:52:00 +0000 (Mon, 17 Sep 2018)");
  script_tag(name:"creation_date", value:"2018-07-11 08:12:02 +0530 (Wed, 11 Jul 2018)");
  script_name("Adobe Flash Player Security Updates(apsb18-24)-MAC OS X");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An out-of-bounds read error.

  - A type Confusion error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to disclose sensitive information and also to conduct arbitrary code
  execution.");

  script_tag(name:"affected", value:"Adobe Flash Player version before
  30.0.0.134 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  30.0.0.134, or later on MAC OS X.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb18-24.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Flash/Player/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"30.0.0.134"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"30.0.0.134", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(0);