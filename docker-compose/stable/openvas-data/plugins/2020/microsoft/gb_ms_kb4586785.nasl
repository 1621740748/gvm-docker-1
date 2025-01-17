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
  script_oid("1.3.6.1.4.1.25623.1.0.817532");
  script_version("2020-11-11T17:29:33+0000");
  script_cve_id("CVE-2020-1599", "CVE-2020-16997", "CVE-2020-16998",
                "CVE-2020-16999", "CVE-2020-17000", "CVE-2020-17001", "CVE-2020-17004",
                "CVE-2020-17007", "CVE-2020-17011", "CVE-2020-17012", "CVE-2020-17013",
                "CVE-2020-17014", "CVE-2020-17024", "CVE-2020-17025",
                "CVE-2020-17026", "CVE-2020-17027", "CVE-2020-17028", "CVE-2020-17029",
                "CVE-2020-17030", "CVE-2020-17031", "CVE-2020-17032", "CVE-2020-17033",
                "CVE-2020-17034", "CVE-2020-17035", "CVE-2020-17036", "CVE-2020-17037",
                "CVE-2020-17038", "CVE-2020-17040", "CVE-2020-17041", "CVE-2020-17042",
                "CVE-2020-17043", "CVE-2020-17044", "CVE-2020-17045",
                "CVE-2020-17046", "CVE-2020-17047", "CVE-2020-17048", "CVE-2020-17052",
                "CVE-2020-17053", "CVE-2020-17054", "CVE-2020-17055", "CVE-2020-17056",
                "CVE-2020-17057", "CVE-2020-17058",
                "CVE-2020-17068", "CVE-2020-17069", "CVE-2020-17070", "CVE-2020-17071",
                "CVE-2020-17075", "CVE-2020-17077", "CVE-2020-17087", "CVE-2020-17088", "CVE-2020-17090", "CVE-2020-17113");
  script_tag(name:"cvss_base", value:"9.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-11-11 17:29:33 +0000 (Wed, 11 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-11 10:31:32 +0530 (Wed, 11 Nov 2020)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4586785)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4586785");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Incorrect processing of user-supplied data in Windows.

  - Error in excessive data output in the Remote Desktop Protocol server.

  - Error in use after free memory in DirectX driver.

  - Error when the Windows WalletService fails to properly impose security restrictions.

  - Error in excessive data output by the application in Windows Graphics Component.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, elevate privilges and disclose sensitive information.");

  script_tag(name:"affected", value:"Microsoft Windows 10 Version 1803 for 32-bit/x64-based Systems.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4586785");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
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

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"User32.dll");
if(!fileVer){
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.17134.0", test_version2:"10.0.17134.1844"))
{
  report = report_fixed_ver(file_checked:dllPath + "\User32.dll",
                            file_version:fileVer, vulnerable_range:"10.0.17134.0 - 10.0.17134.1844");
  security_message(data:report);
  exit(0);
}
exit(99);
