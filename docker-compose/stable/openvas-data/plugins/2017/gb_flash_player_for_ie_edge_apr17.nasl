###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft IE And Microsoft Edge Multiple Flash Player Vulnerabilities (4018483)
#
# Authors:
# Kashinath T <Kashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810845");
  script_version("2020-10-29T15:35:19+0000");
  script_cve_id("CVE-2017-3058", "CVE-2017-3059", "CVE-2017-3060", "CVE-2017-3061",
                "CVE-2017-3062", "CVE-2017-3063", "CVE-2017-3064", "CVE-2015-5122",
                "CVE-2015-5123");
  script_bugtraq_id(97551, 97557, 75712, 75710);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)");
  script_tag(name:"creation_date", value:"2017-04-12 10:07:23 +0530 (Wed, 12 Apr 2017)");
  script_name("Microsoft IE And Microsoft Edge Multiple Flash Player Vulnerabilities (4018483)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft security updates April 2017.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Use-after-free vulnerabilities that could lead to code execution.

  - Memory corruption vulnerabilities that could lead to code execution.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to execute arbitrary code on
  the target user's system and that could potentially allow an attacker to
  take control of the affected system.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1511 for 32-bit/x64 Systems

  - Microsoft Windows 10 Version 1607 for 32-bit/x64 Systems

  - Microsoft Windows 10 Version 1607 for x64-based Systems

  - Microsoft Windows 10 Version 1703 for 32-bit/x64 Systems

  - Microsoft Windows 10 for 32-bit/x64 Systems

  - Microsoft Windows 8.1 for 32-bit/x64 systems

  - Microsoft Windows Server 2012 / 2012 R2 / 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/4018483");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb17-10.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_flash_player_within_ie_edge_detect.nasl");
  script_mandatory_keys("AdobeFlash/IE_or_EDGE/Installed");

  exit(0);
}

include("host_details.inc");
include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012:1, win2012R2:1, win10:1,
                   win10x64:1, win2016:1) <= 0)
  exit(0);

cpe_list = make_list("cpe:/a:adobe:flash_player_internet_explorer", "cpe:/a:adobe:flash_player_edge");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];
if(path) {
  path += "\Flashplayerapp.exe";
} else {
  path = "Could not find the install location";
}

if(version_is_less(version:vers, test_version:"25.0.0.148")) {
  report = report_fixed_ver(file_checked:path, file_version:vers, vulnerable_range:"Less than 25.0.0.148");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
