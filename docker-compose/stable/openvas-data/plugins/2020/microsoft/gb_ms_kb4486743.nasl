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
  script_oid("1.3.6.1.4.1.25623.1.0.817823");
  script_version("2020-11-26T08:02:59+0000");
  script_cve_id("CVE-2020-17064", "CVE-2020-17065", "CVE-2020-17066", "CVE-2020-17067");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-11-26 08:02:59 +0000 (Thu, 26 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-11 09:41:28 +0530 (Wed, 11 Nov 2020)");
  script_name("Microsoft Excel 2010 Service Pack 2 Security Feature Bypass And RCE Vulnerabilities (KB4486743)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4486743");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to microsoft excel
  software when it fails to properly handle specially crafted Office file.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code.");

  script_tag(name:"affected", value:"Microsoft Excel 2010 Service Pack 2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4486743");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Word/Version");
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

exeVer = get_kb_item("SMB/Office/Excel/Version");
if(!exeVer){
  exit(0);
}

exePath = get_kb_item("SMB/Office/Excel/Install/Path");
if(!exePath){
  exePath = "Unable to fetch the install path";
}

if(exeVer =~ "^14\." && version_is_less(version:exeVer, test_version:"14.0.7262.5000"))
{
  report = report_fixed_ver(file_checked:exePath + "Excel.exe",
                            file_version:exeVer, vulnerable_range:"14.0 - 14.0.7262.4999");
  security_message(data:report);
  exit(0);
}
exit(99);
