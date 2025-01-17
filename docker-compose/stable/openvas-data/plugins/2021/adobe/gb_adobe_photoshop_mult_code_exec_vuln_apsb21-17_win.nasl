# Copyright (C) 2021 Greenbone Networks GmbH
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:adobe:photoshop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817970");
  script_version("2021-03-16T11:34:24+0000");
  script_cve_id("CVE-2021-21082", "CVE-2021-21067");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-03-16 11:34:24 +0000 (Tue, 16 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-12 15:19:26 +0530 (Fri, 12 Mar 2021)");
  script_name("Adobe Photoshop Multiple Code Execution Vulnerabilities (APSB21-17) - Windows");

  script_tag(name:"summary", value:"The host is installed with Adobe Photoshop
  and is prone to multiple code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An out-of-bounds write error.

  - A buffer overflow error.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on affected system.");

  script_tag(name:"affected", value:"Adobe Photoshop 2020 21.2.5 and earlier
  and Adobe Photoshop 2021 22.2 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Photoshop 2020 21.2.6
  or Adobe Photoshop 2021 22.3 or later. Please see the references for more
  information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb21-17.html");

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect.nasl");
  script_mandatory_keys("Adobe/Photoshop/Installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^21\.") {
  if(version_is_less(version:vers, test_version:"21.2.6")) {
    fix = "21.2.6";
    installed_ver = "Adobe Photoshop CC 2020";
  }
}

else if(vers =~ "^22\.") {
  if(version_is_less(version:vers, test_version:"22.3")) {
    fix = "22.3";
    installed_ver = "Adobe Photoshop CC 2021";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:installed_ver + " " + vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
