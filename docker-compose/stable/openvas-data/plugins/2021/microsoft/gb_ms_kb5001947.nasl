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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818306");
  script_version("2021-06-17T07:22:39+0000");
  script_cve_id("CVE-2021-31939");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-06-17 07:22:39 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-10 07:45:11 +0530 (Thu, 10 Jun 2021)");
  script_name("Microsoft Excel 2016 RCE Vulnerability (KB5001947)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5001947");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper input validation
  in Microsoft Office software.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Microsoft Excel 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5001947");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Excel/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

vers = get_kb_item("SMB/Office/Excel/Version");
if(!vers){
  exit(0);
}

path = get_kb_item("SMB/Office/Excel/Install/Path");
if(!path){
  path = "Unable to fetch the install path";
}

if(version_in_range(version:vers, test_version:"16.0", test_version2:"16.0.5173.0999"))
{
  report = report_fixed_ver(file_checked:path + "Excel.exe",
                            file_version:vers, vulnerable_range:"16.0 - 16.0.5173.0999");
  security_message(data:report);
  exit(0);
}
exit(99);
