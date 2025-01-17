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
  script_oid("1.3.6.1.4.1.25623.1.0.815797");
  script_version("2020-10-19T15:33:20+0000");
  script_cve_id("CVE-2020-0645", "CVE-2020-0684", "CVE-2020-0768", "CVE-2020-0769",
                "CVE-2020-0770", "CVE-2020-0771", "CVE-2020-0772", "CVE-2020-0773",
                "CVE-2020-0774", "CVE-2020-0778", "CVE-2020-0779", "CVE-2020-0781",
                "CVE-2020-0783", "CVE-2020-0785", "CVE-2020-0787", "CVE-2020-0788",
                "CVE-2020-0791", "CVE-2020-0802", "CVE-2020-0803", "CVE-2020-0804",
                "CVE-2020-0806", "CVE-2020-0814", "CVE-2020-0822", "CVE-2020-0824",
                "CVE-2020-0830", "CVE-2020-0832", "CVE-2020-0833", "CVE-2020-0842",
                "CVE-2020-0843", "CVE-2020-0844", "CVE-2020-0845", "CVE-2020-0847",
                "CVE-2020-0849", "CVE-2020-0853", "CVE-2020-0860", "CVE-2020-0871",
                "CVE-2020-0874", "CVE-2020-0877", "CVE-2020-0879", "CVE-2020-0880",
                "CVE-2020-0881", "CVE-2020-0882", "CVE-2020-0883", "CVE-2020-0885",
                "CVE-2020-0887");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-19 15:33:20 +0000 (Mon, 19 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-03-11 11:49:28 +0530 (Wed, 11 Mar 2020)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4540688)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4540688");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist when,

  - Windows Error Reporting improperly handles memory.

  - Windows GDI component improperly discloses the contents of its memory.

  - Windows Graphics Component improperly handles objects in memory.

  - Windows Network Connections Service improperly handles objects in memory.

  - Connected User Experiences and Telemetry Service improperly handles file
    operations.

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary code, elevate privileges, disclose sensitive information
  and conduct tampering attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 7 for 32-bit/x64 Systems Service Pack 1

  - Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4540688");
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

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) <= 0){
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

if(version_is_less(version:fileVer, test_version:"6.1.7601.24550"))
{
  report = report_fixed_ver(file_checked:dllPath + "\User32.dll",
                            file_version:fileVer, vulnerable_range:"Less than 6.1.7601.24550");
  security_message(data:report);
  exit(0);
}
exit(99);
