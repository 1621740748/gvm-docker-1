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
  script_oid("1.3.6.1.4.1.25623.1.0.818140");
  script_version("2021-06-18T06:56:41+0000");
  script_cve_id("CVE-2021-1675", "CVE-2021-26414", "CVE-2021-31199", "CVE-2021-31201",
                "CVE-2021-31953", "CVE-2021-31954", "CVE-2021-31956", "CVE-2021-31958",
                "CVE-2021-31959", "CVE-2021-31962", "CVE-2021-31968", "CVE-2021-31970",
                "CVE-2021-31971", "CVE-2021-31972", "CVE-2021-31973", "CVE-2021-31974",
                "CVE-2021-31975", "CVE-2021-31976", "CVE-2021-33742");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-06-18 06:56:41 +0000 (Fri, 18 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-09 15:47:12 +0530 (Wed, 09 Jun 2021)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5003671)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5003671");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An error in Windows HTML Platform.

  - An error in Server for NFS.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause denial of service, disclose sensitive information and bypass security
  restrictions.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 for 32-bit/x64-based systems

  - Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5003671");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
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

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) <= 0){
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"urlmon.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"11.0.9600.20045"))
{
  report = report_fixed_ver(file_checked:dllPath + "\urlmon.dll",
                            file_version:fileVer, vulnerable_range:"Less than 11.0.9600.20045");
  security_message(data:report);
  exit(0);
}
exit(99);
