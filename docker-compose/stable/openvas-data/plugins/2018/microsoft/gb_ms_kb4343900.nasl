###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4343900)
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
  script_oid("1.3.6.1.4.1.25623.1.0.813845");
  script_version("2021-06-24T02:00:31+0000");
  script_cve_id("CVE-2018-3615", "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-8316",
                "CVE-2018-8339", "CVE-2018-8341", "CVE-2018-8342", "CVE-2018-8343",
                "CVE-2018-8345", "CVE-2018-8348", "CVE-2018-8349", "CVE-2018-8344",
                "CVE-2018-8351", "CVE-2018-8353", "CVE-2018-8355", "CVE-2018-8346",
                "CVE-2018-8371", "CVE-2018-8372", "CVE-2018-8373", "CVE-2018-8385",
                "CVE-2018-8389", "CVE-2018-8394", "CVE-2018-8396", "CVE-2018-8397",
                "CVE-2018-8398", "CVE-2018-8403", "CVE-2018-8404");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-06-24 02:00:31 +0000 (Thu, 24 Jun 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-10 16:43:00 +0000 (Mon, 10 Sep 2018)");
  script_tag(name:"creation_date", value:"2018-08-15 13:17:43 +0530 (Wed, 15 Aug 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4343900)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4343900");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A new speculative execution side channel vulnerability known as L1 Terminal
    Fault.

  - Internet Explorer improperly validates hyperlinks before loading executable
    libraries.

  - Windows Installer fails to properly sanitize input leading to an insecure library
    loading behavior.

  - NDIS fails to check the length of a buffer prior to copying memory to it.

  - Windows font library improperly handles specially crafted embedded fonts.

  - An improper processing for a .LNK file.

  - 'Microsoft COM for Windows' fails to properly handle serialized objects.

  - Microsoft browsers improperly allow cross-frame interaction.

  - Microsoft browsers allowing sandbox escape.

  - Microsoft Edge improperly handles redirect requests and specific HTML content.

  - Microsoft .NET Framework improperly access information in multi-tenant environments.

  - WebAudio Library improperly handles audio requests.

  - Windows GDI component improperly discloses the contents of its memory.

  - Windows PDF Library improperly handles objects in memory.

  - Windows Shell does not properly validate file paths.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, run processes in an elevated context, obtain
  information to further compromise the user's system, trick a user into believing
  that the user was on a legitimate website, read privileged data across trust
  boundaries and also bypass certain security restrictions.");

  script_tag(name:"affected", value:"- Microsoft Windows 7 for 32-bit/x64 Systems Service Pack 1

  - Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4343900");
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

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

msVer = fetch_file_version(sysPath:sysPath, file_name:"Mshtml.dll");
if(!msVer){
  exit(0);
}

if(version_is_less(version:msVer, test_version:"11.0.9600.19101"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Mshtml.dll",
                            file_version:msVer, vulnerable_range:"Less than 11.0.9600.19101");
  security_message(data:report);
  exit(0);
}
