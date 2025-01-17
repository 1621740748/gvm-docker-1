###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Photoshop CC Remote Code Execution Vulnerability May18 (Mac OS X)
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.812890");
  script_version("2021-06-02T11:05:57+0000");
  script_cve_id("CVE-2018-4946");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-06-02 11:05:57 +0000 (Wed, 02 Jun 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-12 15:12:00 +0000 (Wed, 12 Sep 2018)");
  script_tag(name:"creation_date", value:"2018-05-16 11:46:20 +0530 (Wed, 16 May 2018)");
  script_name("Adobe Photoshop CC Remote Code Execution Vulnerability May18 (Mac OS X)");

  script_tag(name:"summary", value:"The host is installed with Adobe Photoshop
  CC and is prone to remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an out of bounds
  write error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the user running the
  affected application and gain elevated privileges.");

  script_tag(name:"affected", value:"Adobe Photoshop CC 2017 18.1.3 and earlier
  and Adobe Photoshop CC 2018 19.1.3 and earlier versions on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Photoshop CC 2017
  18.1.4 or Photoshop CC 2018 19.1.4 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb18-17.html");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Photoshop/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:adobe:photoshop_cc2017", "cpe:/a:adobe:photoshop_cc2018");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^18\.") {
  if(version_is_less_equal(version:vers, test_version:"18.1.3")) {
    fix = "18.1.4";
    installed_ver = "Adobe Photoshop CC 2017";
  }
}

else if(vers =~ "^19\.") {
  if(version_is_less_equal(version:vers, test_version:"19.1.3")) {
    fix = "19.1.4";
    installed_ver = "Adobe Photoshop CC 2018";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:installed_ver + " " + vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
