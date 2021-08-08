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


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817313");
  script_version("2020-10-28T08:50:02+0000");
  script_cve_id("CVE-2020-1449", "CVE-2020-1445", "CVE-2020-1342", "CVE-2020-1447",
                "CVE-2020-1446", "CVE-2020-1458", "CVE-2020-1240", "CVE-2020-1349");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-28 08:50:02 +0000 (Wed, 28 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-07-27 11:50:35 +0530 (Mon, 27 Jul 2020)");
  script_name("Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities-July20");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Office Click-to-Run updates.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in Microsoft Excel because it fails to properly handle objects in memory.

  - An error in Microsoft Outlook because it fails to properly handle objects in memory.

  - An error in Microsoft Project because it fails to check the source markup of a file.

  - An error when Microsoft Office improperly discloses the contents of its memory.

  - An error when Microsoft Office software reads out of bound memory due to
    an uninitialized variable.

  - Multiple errors in Microsoft Word because it fails to properly handle objects in memory.

  - An error when Microsoft Office improperly validates input before loading
    dynamic link library (DLL) files.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code and disclose sensitive information.");

  script_tag(name:"affected", value:"Microsoft Office 365 (2016 Click-to-Run).");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/office365-proplus-security-updates");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_office_click2run_detect_win.nasl");
  script_mandatory_keys("MS/Off/C2R/Ver", "MS/Office/C2R/UpdateChannel");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

officeVer = get_kb_item("MS/Off/C2R/Ver");
if(!officeVer || officeVer !~ "^16\."){
  exit(0);
}

UpdateChannel = get_kb_item("MS/Office/C2R/UpdateChannel");
officePath = get_kb_item("MS/Off/C2R/InstallPath");

## Version 2006 (Build 13001.20384)
# Monthly Channel renamed to Current Channel
if(UpdateChannel == "Monthly Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.13001.20384")){
    fix = "2006 (Build 13001.20384)";
  }
}

## Semi-Annual Channel (Targeted) renamed to Semi-Annual Enterprise Channel (Preview)
## Version 2002 (Build 12527.20880)
else if(UpdateChannel == "Semi-Annual Channel (Targeted)")
{
  if(version_is_less(version:officeVer, test_version:"16.0.12527.20880")){
    fix = "2002 (Build 12527.20880)";
  }
}

##Version 1908 (Build 11929.20838)
##Version 1902 (Build 11328.20624)
##Version 2002 (Build 12527.20880)
## Semi-Annual Channel renamed to Semi-Annual Enterprise Channel
else if(UpdateChannel == "Semi-Annual Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.11328.20624")){
    fix = "1902 (Build 11328.20624)";
  }

  else if(version_in_range(version:officeVer, test_version:"16.0.11929", test_version2:"16.0.11929.20903")){
    fix = "1908 (Build 11929.20904)";
  }

  else if(version_in_range(version:officeVer, test_version:"16.0.12527", test_version2:"16.0.12527.20879")){
    fix = "2002 (Build 12527.20880)";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(data:report);
  exit(0);
}
exit(99);
