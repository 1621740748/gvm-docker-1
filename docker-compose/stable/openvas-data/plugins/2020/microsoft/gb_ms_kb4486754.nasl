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
  script_oid("1.3.6.1.4.1.25623.1.0.817847");
  script_version("2020-12-15T08:26:52+0000");
  script_cve_id("CVE-2020-17128", "CVE-2020-17123", "CVE-2020-17125", "CVE-2020-17126",
                "CVE-2020-17130", "CVE-2020-17129");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-12-15 08:26:52 +0000 (Tue, 15 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-09 10:39:05 +0530 (Wed, 09 Dec 2020)");
  script_name("Microsoft Excel 2016 Security Feature Bypass And RCE Vulnerabilities (KB4486754)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4486754");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to microsoft excel
  software fails to properly handle specially crafted Office file.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct remote code execution.");

  script_tag(name:"affected", value:"Microsoft Excel 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4486754");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Excel/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

excelVer = get_kb_item("SMB/Office/Excel/Version");
if(!excelVer){
  exit(0);
}

excelPath = get_kb_item("SMB/Office/Excel/Install/Path");
if(!excelPath){
  excelPath = "Unable to fetch the install path";
}

if(version_in_range(version:excelVer, test_version:"16.0", test_version2:"16.0.5095.0999"))
{
  report = report_fixed_ver(file_checked:excelPath + "Excel.exe",
                            file_version:excelVer, vulnerable_range:"16.0 - 16.0.5095.0999");
  security_message(data:report);
  exit(0);
}
exit(99);
