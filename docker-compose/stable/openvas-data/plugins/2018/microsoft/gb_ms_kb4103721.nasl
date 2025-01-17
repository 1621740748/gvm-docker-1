###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4103721)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813339");
  script_version("2021-06-23T02:00:29+0000");
  script_cve_id("CVE-2018-0765", "CVE-2018-0954", "CVE-2018-0955", "CVE-2018-0958",
                "CVE-2018-0959", "CVE-2018-0961", "CVE-2018-1022", "CVE-2018-1025",
                "CVE-2018-1039", "CVE-2018-8112", "CVE-2018-8114", "CVE-2018-8122",
                "CVE-2018-8124", "CVE-2018-8126", "CVE-2018-8127", "CVE-2018-8128",
                "CVE-2018-8129", "CVE-2018-8130", "CVE-2018-8132", "CVE-2018-8133",
                "CVE-2018-8134", "CVE-2018-8136", "CVE-2018-8137", "CVE-2018-8139",
                "CVE-2018-8145", "CVE-2018-8164", "CVE-2018-8165", "CVE-2018-8166",
                "CVE-2018-8167", "CVE-2018-8174", "CVE-2018-8178", "CVE-2018-8179",
                "CVE-2018-8897", "CVE-2018-0824", "CVE-2018-0943", "CVE-2018-0945",
                "CVE-2018-0946", "CVE-2018-0953", "CVE-2018-0886");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-06-23 02:00:29 +0000 (Wed, 23 Jun 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-05-09 10:15:05 +0530 (Wed, 09 May 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4103721)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4103721");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Windows Common Log File System (CLFS) driver improperly handles objects in
    memory.

  - The Win32k component fails to properly handle objects in memory.

  - The DirectX Graphics Kernel (DXGKRNL) driver improperly handles objects
    in memory.

  - Windows kernel fails to properly handle objects in memory.

  - Scripting engine properly handles objects in memory in microsoft browsers.

  - Chakra improperly discloses the contents of its memory.

  - Internet Explorer fails to validate User Mode Code Integrity (UMCI) policies.

  - Microsoft browsers improperly handle objects in memory.

  - Windows Hyper-V on a host server fails to properly validate vSMB packet
    data.

  - Chakra scripting engine handles objects in memory in Microsoft Edge.

  - Windows Kernel API improperly enforces permissions.

  - Microsoft Edge improperly handles requests of different origins.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run processes in an elevated context, run arbitrary code in kernel mode,
  circumvent a User Mode Code Integrity (UMCI) policy on the machine, gain the
  same user rights as the current user, discloses information to further
  compromise the user's computer or data, interrupt system functionality and cause
  denial of service condition.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1803 for 32-bit Systems

  - Microsoft Windows 10 Version 1803 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4103721");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

if(version_in_range(version:edgeVer, test_version:"11.0.17134.0", test_version2:"11.0.17134.47"))
{
  report = report_fixed_ver(file_checked:sysPath + "\edgehtml.dll",
                            file_version:edgeVer, vulnerable_range:"11.0.17134.0 - 11.0.17134.47");
  security_message(data:report);
  exit(0);
}
exit(99);
