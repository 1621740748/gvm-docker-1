# Copyright (C) 2019 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814910");
  script_version("2020-10-20T05:31:32+0000");
  script_cve_id("CVE-2019-0555", "CVE-2019-0590", "CVE-2019-0591", "CVE-2019-0593",
                "CVE-2019-0595", "CVE-2019-0596", "CVE-2019-0597", "CVE-2019-0598",
                "CVE-2019-0599", "CVE-2019-0600", "CVE-2019-0601", "CVE-2019-0602",
                "CVE-2019-0605", "CVE-2019-0606", "CVE-2019-0607", "CVE-2019-0610",
                "CVE-2019-0613", "CVE-2019-0615", "CVE-2019-0616", "CVE-2019-0618",
                "CVE-2019-0619", "CVE-2019-0621", "CVE-2019-0623", "CVE-2019-0625",
                "CVE-2019-0626", "CVE-2019-0627", "CVE-2019-0628", "CVE-2019-0630",
                "CVE-2019-0631", "CVE-2019-0632", "CVE-2019-0633", "CVE-2019-0634",
                "CVE-2019-0635", "CVE-2019-0636", "CVE-2019-0637", "CVE-2019-0640",
                "CVE-2019-0641", "CVE-2019-0642", "CVE-2019-0644", "CVE-2019-0645",
                "CVE-2019-0649", "CVE-2019-0651", "CVE-2019-0652", "CVE-2019-0654",
                "CVE-2019-0655", "CVE-2019-0656", "CVE-2019-0657", "CVE-2019-0658",
                "CVE-2019-0659", "CVE-2019-0660", "CVE-2019-0662", "CVE-2019-0676");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-20 05:31:32 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2019-02-13 13:39:27 +0530 (Wed, 13 Feb 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4486996)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4486996");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Please see the references for more information
  on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to obtain information to further compromise the user's system, gain elevated
  privileges on an affected system and execute arbitrary code in the context of
  the current user.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1709 for 32-bit Systems

  - Microsoft Windows 10 Version 1709 for 64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4486996");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer){
  exit(0);
}

if(version_in_range(version:edgeVer, test_version:"11.0.16299.0", test_version2:"11.0.16299.966"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Edgehtml.dll",
                            file_version:edgeVer, vulnerable_range:"11.0.16299.0 - 11.0.16299.966");
  security_message(data:report);
  exit(0);
}
exit(99);
