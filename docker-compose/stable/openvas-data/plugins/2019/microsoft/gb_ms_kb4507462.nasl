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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815514");
  script_version("2020-10-29T15:35:19+0000");
  script_cve_id("CVE-2019-0683", "CVE-2019-0785", "CVE-2019-0880", "CVE-2019-0887",
                "CVE-2019-1004", "CVE-2019-1006", "CVE-2019-1059", "CVE-2019-1063",
                "CVE-2019-1071", "CVE-2019-1073", "CVE-2019-1082", "CVE-2019-1085",
                "CVE-2019-1088", "CVE-2019-1089", "CVE-2019-1093", "CVE-2019-1094",
                "CVE-2019-1095", "CVE-2019-1096", "CVE-2019-1097", "CVE-2019-1102",
                "CVE-2019-1104", "CVE-2019-1108", "CVE-2019-1125", "CVE-2019-1130");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)");
  script_tag(name:"creation_date", value:"2019-07-10 09:30:27 +0530 (Wed, 10 Jul 2019)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4507462)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4480963");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - DHCP failover servers improperly handle network packets.

  - splwow64.exe improperly handles certain calls.

  - Remote Desktop Services improperly handles clipboard redirection.

  - Windows Communication Foundation (WCF) and Windows Identity Foundation (WIF),
    allow signing of SAML tokens with arbitrary symmetric keys.

  - Kernel Information Disclosure Vulnerability (SWAPGS Attack).

  Please see the references for more information about the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, elevate privileges, bypass authentication and disclose
  sensitive information.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2012.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4507462");
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

if(hotfix_check_sp(win2012:1) <= 0){
  exit(0);
}

dllpath = smb_get_system32root();
if(!dllpath)
  exit(0);

fileVer = fetch_file_version(sysPath:dllpath, file_name:"Gdi32.dll");
if(!fileVer)
  exit(0);

if(version_is_less(version:fileVer, test_version:"6.2.9200.22802")) {
  report = report_fixed_ver(file_checked:dllpath + "\Gdi32.dll",
                            file_version:fileVer, vulnerable_range:"Less than 6.2.9200.22802");
  security_message(data:report);
  exit(0);
}

exit(99);
