###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Reader/Acrobat Security Bypass Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902387");
  script_version("2020-05-28T14:41:23+0000");
  script_cve_id("CVE-2011-2102");
  script_bugtraq_id(48253);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-05-28 14:41:23 +0000 (Thu, 28 May 2020)");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_name("Adobe Reader/Acrobat Security Bypass Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host has Adobe Reader/Acrobat installed, and is/are prone to security
  bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is caused by an unknown vectors, allows attackers to bypass intended
  access restriction.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to bypass intended security
  restrictions, which may leads to the other attacks.");

  script_tag(name:"affected", value:"Adobe Reader version 10.0.1 and prior.

  Adobe Acrobat version 10.0.1 and prior.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat and Reader version 10.1 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-16.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");

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

if(vers =~ "^10\." && version_is_less(version:vers, test_version:"10.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"10.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
} else if(vers =~ "^9\." && version_is_less(version:vers, test_version:"9.4.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"9.4.5", install_path:path);
  security_message(port:0, data:report);
  exit(0);
} else if(vers =~ "^8\." && version_is_less(version:vers, test_version:"8.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.3", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);