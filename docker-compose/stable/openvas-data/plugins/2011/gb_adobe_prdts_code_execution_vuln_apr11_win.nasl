###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Products Arbitrary Code Execution Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801921");
  script_version("2020-05-28T14:41:23+0000");
  script_cve_id("CVE-2011-0611");
  script_bugtraq_id(47314);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-05-28 14:41:23 +0000 (Thu, 28 May 2020)");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_name("Adobe Products Arbitrary Code Execution Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host has Adobe Acrobat or Adobe Reader or Adobe flash Player installed
  and is prone to code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in handling 'SWF' file in adobe flash player and
  'Authplay.dll' in Adobe acrobat/reader. which allows attackers to execute
  arbitrary code or cause a denial of service via crafted flash content.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to corrupt memory and execute
  arbitrary code on the system with elevated privileges.");

  script_tag(name:"affected", value:"Adobe Flash Player version 10.2.153.1 and prior on Windows.

  Adobe Reader/Acrobat version 9.x to 9.4.3 and 10.x to 10.0.2 on Windows.");

  script_tag(name:"solution", value:"Upgrade adobe flash player to version 10.2.159.1 or later,
  Update Adobe Reader/Acrobat to version 9.4.4 or 10.0.3 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/230057");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa11-02.html");
  script_xref(name:"URL", value:"http://blogs.adobe.com/psirt/2011/04/security-advisory-for-adobe-flash-player-adobe-reader-and-acrobat-apsa11-02.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl", "gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:adobe:acrobat_reader",
                     "cpe:/a:adobe:acrobat",
                     "cpe:/a:adobe:flash_player");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];
cpe  = infos["cpe"];

if(cpe == "cpe:/a:adobe:acrobat_reader" || cpe ==  "cpe:/a:adobe:acrobat") {
  if(version_in_range(version:vers, test_version:"9.0", test_version2:"9.4.3") ||
     version_in_range(version:vers, test_version:"10.0", test_version2:"10.0.2")){
    report = report_fixed_ver(installed_version:vers, fixed_version:"9.4.4 or 10.0.3", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
} else if(cpe == "cpe:/a:adobe:flash_player") {
  if(version_is_less_equal(version:vers, test_version:"10.2.153.1")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"10.2.159.1", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
